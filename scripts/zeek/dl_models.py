#!/usr/bin/env python3
"""Modelos de deep learning (PyTorch) sobre la SECUENCIA de bytes del payload y
utilidades de entrenamiento/evaluacion compartidas por la Fase 3.

Los datasets de la Fase 2 guardan `X_seq` (N, 256) uint8: los primeros 256 bytes
del payload de cada flujo (0-padded). Aqui cada byte 0-255 se trata como un TOKEN
con un embedding aprendido, y encima se montan:

  - ByteCNN: CNN 1D multi-kernel (kernels 3/5/7) estilo TextCNN / "Deep Packet".
    Cada filtro convolucional aprende un detector de n-gramas de bytes (p. ej. la
    secuencia de bytes de `union select` o `<script>`); el max-pooling global se
    queda con la activacion mas fuerte de cada filtro en el flujo.
  - ByteLSTM: BiLSTM sobre la misma secuencia de embeddings (contexto secuencial),
    para contrastar convolucion vs recurrencia.
  - ByteTransformer (24-ago): encoder Transformer con autoatencion sobre la misma
    secuencia. Es la familia que el estado del arte (ET-BERT, DeBERTav2) declara
    superior para payload, pero SIN preentrenamiento ni tokenizacion: entrenado
    de cero sobre el alfabeto de 256 bytes, para que la comparacion con el
    byte-CNN sea a igualdad de datos y de presupuesto.
  - CrossAttentionNet (24-ago): fusion payload<->metadatos por ATENCION CRUZADA,
    la alternativa que propone el estado del arte (CPS-IDS) a la fusion tardia
    por concatenacion del Eje B.

Se entrena en CPU (torch+cpu). Reproducibilidad fijada con semilla global.
"""

from __future__ import annotations

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset

SEED = 42
VOCAB = 256  # bytes 0-255


def set_seed(seed: int = SEED) -> None:
    np.random.seed(seed)
    torch.manual_seed(seed)


class ByteCNN(nn.Module):
    """Embedding de bytes + convoluciones 1D multi-kernel + max-pool global."""

    def __init__(self, n_classes: int, emb: int = 24,
                 kernels=(3, 5, 7), n_filters: int = 64, dropout: float = 0.3):
        super().__init__()
        self.emb = nn.Embedding(VOCAB, emb)
        self.convs = nn.ModuleList(
            [nn.Conv1d(emb, n_filters, k, padding=k // 2) for k in kernels])
        self.drop = nn.Dropout(dropout)
        self.fc = nn.Linear(n_filters * len(kernels), n_classes)

    def forward(self, x):                     # x: (B, L) long
        e = self.emb(x).transpose(1, 2)        # (B, emb, L)
        feats = [F.relu(c(e)).max(dim=2).values for c in self.convs]
        h = torch.cat(feats, dim=1)            # (B, n_filters*len(kernels))
        return self.fc(self.drop(h))


class ByteLSTM(nn.Module):
    """Embedding de bytes + BiLSTM + max-pool temporal."""

    def __init__(self, n_classes: int, emb: int = 24, hidden: int = 64,
                 dropout: float = 0.3):
        super().__init__()
        self.emb = nn.Embedding(VOCAB, emb)
        self.lstm = nn.LSTM(emb, hidden, batch_first=True, bidirectional=True)
        self.drop = nn.Dropout(dropout)
        self.fc = nn.Linear(hidden * 2, n_classes)

    def forward(self, x):                     # x: (B, L) long
        e = self.emb(x)                        # (B, L, emb)
        out, _ = self.lstm(e)                  # (B, L, 2*hidden)
        h = out.max(dim=1).values              # (B, 2*hidden)
        return self.fc(self.drop(h))


class ByteTransformer(nn.Module):
    """Encoder Transformer sobre la secuencia de bytes (autoatencion).

    La familia que el estado del arte situa por encima del CNN para payload
    (ET-BERT, DeBERTav2). Aqui va SIN preentrenar y sin tokenizador: embedding
    de bytes + codificacion posicional aprendida + N capas de encoder, y se
    clasifica con un token [CLS] al principio de la secuencia, que es como
    MambaNetBurst absorbe la representacion agregada.

    Se mantiene deliberadamente pequeno (2 capas, 4 cabezas) para que compita
    con el byte-CNN a igualdad de presupuesto: la pregunta no es si un modelo
    enorme gana, sino si la AUTOATENCION aporta algo sobre la convolucion en
    ESTOS datos.
    """

    def __init__(self, n_classes: int, emb: int = 32, n_heads: int = 4,
                 n_layers: int = 2, ff: int = 128, dropout: float = 0.3,
                 max_len: int = 257):
        super().__init__()
        self.emb = nn.Embedding(VOCAB, emb)
        self.cls = nn.Parameter(torch.zeros(1, 1, emb))
        self.pos = nn.Parameter(torch.zeros(1, max_len, emb))
        capa = nn.TransformerEncoderLayer(
            d_model=emb, nhead=n_heads, dim_feedforward=ff, dropout=dropout,
            batch_first=True, norm_first=True)
        self.enc = nn.TransformerEncoder(capa, num_layers=n_layers)
        self.drop = nn.Dropout(dropout)
        self.fc = nn.Linear(emb, n_classes)
        nn.init.normal_(self.pos, std=0.02)
        nn.init.normal_(self.cls, std=0.02)

    def forward(self, x):                      # x: (B, L) long
        e = self.emb(x)                                    # (B, L, emb)
        cls = self.cls.expand(e.size(0), -1, -1)           # (B, 1, emb)
        h = torch.cat([cls, e], dim=1)                     # (B, L+1, emb)
        h = h + self.pos[:, : h.size(1)]
        h = self.enc(h)
        return self.fc(self.drop(h[:, 0]))                 # token [CLS]


class CrossAttentionNet(nn.Module):
    """Fusion payload <-> metadatos por ATENCION CRUZADA (dos ramas).

    El Eje B funde concatenando los embeddings de las dos ramas (fusion tardia).
    El estado del arte (CPS-IDS) propone algo mas fuerte: que cada vista PONDERE
    a la otra, de modo que el modelo verifique la asercion condicional "¿coincide
    lo sospechoso de estos bytes con una anomalia en el comportamiento del flujo?"

    Implementacion: la rama de metadatos produce una consulta (query) que atiende
    sobre los mapas convolucionales del payload, y viceversa. Las dos salidas
    atendidas se concatenan con los embeddings originales antes de clasificar,
    asi que la red puede usar la fusion cruzada Y las vistas por separado.
    """

    def __init__(self, n_classes: int, n_meta: int, emb: int = 24,
                 kernels=(3, 5, 7), n_filters: int = 64, d: int = 64,
                 n_heads: int = 4, dropout: float = 0.3):
        super().__init__()
        self.emb = nn.Embedding(VOCAB, emb)
        self.convs = nn.ModuleList(
            [nn.Conv1d(emb, n_filters, k, padding=k // 2) for k in kernels])
        pay_dim = n_filters * len(kernels)
        self.pay_proj = nn.Linear(n_filters, d)      # cada posicion -> d
        self.meta = nn.Sequential(
            nn.Linear(n_meta, d), nn.ReLU(), nn.Linear(d, d), nn.ReLU())
        self.att_m2p = nn.MultiheadAttention(d, n_heads, batch_first=True)
        self.att_p2m = nn.MultiheadAttention(d, n_heads, batch_first=True)
        self.drop = nn.Dropout(dropout)
        self.fc = nn.Linear(pay_dim + d * 3, n_classes)

    def forward(self, x_seq, x_meta):
        e = self.emb(x_seq).transpose(1, 2)                  # (B, emb, L)
        mapas = [F.relu(c(e)) for c in self.convs]           # cada (B, F, L)
        # vista global del payload (como el Eje B), para no perder nada
        pf = torch.cat([m.max(dim=2).values for m in mapas], dim=1)
        # secuencia de posiciones del primer kernel, proyectada a d
        seq = self.pay_proj(mapas[0].transpose(1, 2))        # (B, L, d)
        mf = self.meta(x_meta)                               # (B, d)
        q = mf.unsqueeze(1)                                  # (B, 1, d)
        # metadatos -> payload: ¿que posiciones del payload importan dado el flujo?
        a_m2p, _ = self.att_m2p(q, seq, seq)                 # (B, 1, d)
        # payload -> metadatos: el resumen del payload pondera la vista de flujo
        a_p2m, _ = self.att_p2m(seq.mean(dim=1, keepdim=True), q, q)
        h = torch.cat([pf, mf, a_m2p.squeeze(1), a_p2m.squeeze(1)], dim=1)
        return self.fc(self.drop(h))


MODELS = {"cnn": ByteCNN, "lstm": ByteLSTM, "transformer": ByteTransformer}


def train_torch(model, X, y, *, epochs: int, batch: int = 64, lr: float = 1e-3,
                class_weight=None) -> None:
    """Bucle de entrenamiento estandar (Adam + CrossEntropy)."""
    model.train()
    ds = TensorDataset(torch.as_tensor(X, dtype=torch.long),
                       torch.as_tensor(y, dtype=torch.long))
    dl = DataLoader(ds, batch_size=batch, shuffle=True)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    w = None if class_weight is None else torch.as_tensor(class_weight, dtype=torch.float32)
    lossf = nn.CrossEntropyLoss(weight=w)
    for _ in range(epochs):
        for xb, yb in dl:
            opt.zero_grad()
            loss = lossf(model(xb), yb)
            loss.backward()
            opt.step()


def predict_torch(model, X, batch: int = 256) -> np.ndarray:
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(X), batch):
            xb = torch.as_tensor(X[i:i + batch], dtype=torch.long)
            out.append(model(xb).argmax(1).numpy())
    return np.concatenate(out) if out else np.array([], dtype=int)


def predict_proba_torch(model, X, batch: int = 256) -> np.ndarray:
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(X), batch):
            xb = torch.as_tensor(X[i:i + batch], dtype=torch.long)
            out.append(F.softmax(model(xb), dim=1).numpy())
    return np.concatenate(out) if out else np.zeros((0,))


def oof_predict_torch(model_name, X_seq, y_enc, n_classes, *, epochs: int,
                      folds: int = 5, class_weight=None, seed: int = SEED):
    """Predicciones out-of-fold (StratifiedKFold) de un modelo torch: cada flujo
    se predice con un modelo que NO lo entreno. Devuelve (y_pred, y_proba)."""
    from sklearn.model_selection import StratifiedKFold

    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    y_pred = np.zeros(len(y_enc), dtype=int)
    y_proba = np.zeros((len(y_enc), n_classes), dtype=np.float32)
    for tr, va in skf.split(X_seq, y_enc):
        set_seed(seed)
        model = MODELS[model_name](n_classes)
        train_torch(model, X_seq[tr], y_enc[tr], epochs=epochs, class_weight=class_weight)
        y_pred[va] = predict_torch(model, X_seq[va])
        y_proba[va] = predict_proba_torch(model, X_seq[va])
    return y_pred, y_proba
