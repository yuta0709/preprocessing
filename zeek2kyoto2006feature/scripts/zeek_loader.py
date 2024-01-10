from typing import Optional, List
from dataclasses import dataclass
import numpy as np

import pandas as pd
from pandas import DataFrame


@dataclass
class ZeekLogSchema:
    ts_str: str
    ts: float  # タイムスタンプ
    uid: str  # 一意の接続ID
    id_orig_h: str  # 送信元ホストアドレス
    id_orig_p: int  # 送信元ポート番号
    id_resp_h: str  # 宛先ホストアドレス
    id_resp_p: int  # 宛先ポート番号
    proto: str  # トランスポートプロトコル
    service: Optional[str]  # 検出されたサービス（ない場合もある）
    duration: Optional[float]  # 接続の持続時間（秒）
    orig_bytes: Optional[int]  # 送信元から宛先へのバイト数
    resp_bytes: Optional[int]  # 宛先から送信元へのバイト数
    conn_state: str  # 接続の状態
    local_orig: Optional[str]  # ローカルで生成された接続かどうか
    local_resp: Optional[str]  # ローカルで受信された接続かどうか
    missed_bytes: int  # 欠落したバイト数
    history: str  # 接続のイベント履歴
    orig_pkts: int  # 送信元から宛先へのパケット数
    orig_ip_bytes: int  # 送信元から宛先へのIPバイト数
    resp_pkts: int  # 宛先から送信元へのパケット数
    resp_ip_bytes: int  # 宛先から送信元へのIPバイト数
    tunnel_parents: Optional[str]  # トンネルの親接続（あれば）


def load_zeek_log(file_path: str) -> List[ZeekLogSchema]:
    column_names = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
        "local_orig",
        "local_resp",
        "missed_bytes",
        "history",
        "orig_pkts",
        "orig_ip_bytes",
        "resp_pkts",
        "resp_ip_bytes",
        "tunnel_parents",
    ]
    df = pd.read_csv(
        file_path,
        sep="\t",
        header=None,
        names=column_names,
        comment="#",
        na_values="-",
        dtype={"ts": str},
    )
    zeek_logs = []
    for i, row in df.iterrows():
        ts_str = row["ts"]
        ts = float(ts_str)
        uid = row["uid"]
        id_orig_h = row["id.orig_h"]
        id_orig_p = row["id.orig_p"]
        id_resp_h = row["id.resp_h"]
        id_resp_p = row["id.resp_p"]
        proto = row["proto"]
        service = row["service"] if not pd.isna(row["service"]) else None
        duration = row["duration"] if not pd.isna(row["duration"]) else None
        orig_bytes = row["orig_bytes"] if not pd.isna(row["orig_bytes"]) else None
        resp_bytes = row["resp_bytes"] if not pd.isna(row["resp_bytes"]) else None
        conn_state = row["conn_state"]
        local_orig = row["local_orig"] if not pd.isna(row["local_orig"]) else None
        local_resp = row["local_resp"] if not pd.isna(row["local_resp"]) else None
        missed_bytes = row["missed_bytes"]
        history = str(row["history"])
        orig_pkts = row["orig_pkts"]
        orig_ip_bytes = row["orig_ip_bytes"]
        resp_pkts = row["resp_pkts"]
        resp_ip_bytes = row["resp_ip_bytes"]
        tunnel_parents = (
            row["tunnel_parents"] if not pd.isna(row["tunnel_parents"]) else None
        )
        log = ZeekLogSchema(
            ts_str,
            ts,
            uid,
            id_orig_h,
            id_orig_p,
            id_resp_h,
            id_resp_p,
            proto,
            service,
            duration,
            orig_bytes,
            resp_bytes,
            conn_state,
            local_orig,
            local_resp,
            missed_bytes,
            history,
            orig_pkts,
            orig_ip_bytes,
            resp_pkts,
            resp_ip_bytes,
            tunnel_parents,
        )
        zeek_logs.append(log)

    return zeek_logs
