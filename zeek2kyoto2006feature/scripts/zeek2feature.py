import csv
from dataclasses import dataclass, asdict
from typing import List
import argparse
import os

from zeek_loader import load_zeek_log, ZeekLogSchema


@dataclass
class Kyoto2006Feature:
    unix_s: int
    unix_ns: int
    duration: float
    service: str
    source_bytes: int
    destination_byets: int
    count: int
    same_srv_rate: float
    serror_rate: float
    srv_serror_rate: float
    dst_host_count: int
    dst_host_srv_count: int
    dst_host_same_src_port_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    flag: str


def value_or_zero(x):
    if x is not None:
        return x
    else:
        return 0


def is_last_2sec_session(c: ZeekLogSchema, x: ZeekLogSchema) -> bool:
    d = c.ts - x.ts
    return d <= 2 and 0 <= d and c.uid != x.uid


def is_same_dst_ip(x: ZeekLogSchema, y: ZeekLogSchema) -> bool:
    return x.id_resp_h == y.id_resp_h


def is_older_session(c: ZeekLogSchema, x: ZeekLogSchema) -> bool:
    return x.ts <= c.ts and c.uid != x.uid


def is_same_dst_host_ip(x: ZeekLogSchema, y: ZeekLogSchema) -> bool:
    return x.id_orig_h == y.id_orig_h and x.id_resp_h == y.id_resp_h


def is_same_dst_port(x: ZeekLogSchema, y: ZeekLogSchema) -> bool:
    return x.id_resp_p == y.id_resp_p


def is_same_dst_ip_and_srv(x: ZeekLogSchema, y: ZeekLogSchema) -> bool:
    return x.id_resp_h == y.id_resp_h and x.service == y.service


def is_same_src_port(x: ZeekLogSchema, y: ZeekLogSchema) -> bool:
    return x.id_orig_p == y.id_orig_p


def zeeklog_sort(x: ZeekLogSchema):
    return x.ts


def is_syn_error(x: ZeekLogSchema) -> bool:
    return x.conn_state == "S0"


def write_to_csv(features, filename):
    with open(filename, "w", newline="") as csvfile:
        fieldnames = list(asdict(features[0]).keys())
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for feature in features:
            writer.writerow(asdict(feature))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename")
    parser.add_argument("output_dir")
    args = parser.parse_args()
    file_path = args.filename
    output_dir = args.output_dir
    zeek_logs = load_zeek_log(file_path)
    zeek_logs = sorted(zeek_logs, key=zeeklog_sort)
    features: List[Kyoto2006Feature] = []
    for log in zeek_logs:
        unix_s = int(log.ts_str.split(".")[0])
        unix_ns = int(log.ts_str.split(".")[1]) * 1000
        duration = log.duration if log.duration is not None else 0.0

        service = log.service if log.service is not None else "others"

        source_bytes = value_or_zero(log.orig_bytes)

        destination_bytes = value_or_zero(log.resp_bytes)

        last_2sec_sessions = filter(lambda x: is_last_2sec_session(log, x), zeek_logs)
        count_feature_sessions = list(
            filter(lambda x: is_same_dst_ip(log, x), last_2sec_sessions)
        )
        count = len(count_feature_sessions)

        same_srv_rate = (
            (
                len(
                    list(
                        filter(
                            lambda x: x.service == log.service, count_feature_sessions
                        )
                    )
                )
                / count
            )
            if count != 0
            else 0.0
        )

        serror_rate = (
            (
                len(
                    list(
                        filter(
                            lambda x: x.conn_state == "S0",
                            count_feature_sessions,
                        )
                    )
                )
                / count
            )
            if count != 0
            else 0.0
        )

        last_2sec_same_service_sessions = filter(
            lambda x: x.service == log.service, last_2sec_sessions
        )
        srv_serror_rate = (
            (
                len(
                    list(
                        filter(
                            lambda x: x.conn_state == "S0",
                            last_2sec_same_service_sessions,
                        )
                    )
                )
                / count
            )
            if count != 0
            else 0.0
        )

        past_sessions = filter(lambda x: (is_older_session(log, x)), zeek_logs)
        past_same_dst_port_sessions = filter(
            lambda x: is_same_dst_port(x, log), past_sessions
        )
        past_same_dst_port_100_sessions = list(past_same_dst_port_sessions)[-100:]

        dst_host_count_feature_sessions = list(
            filter(
                lambda x: is_same_dst_host_ip(x, log),
                past_same_dst_port_100_sessions,
            )
        )
        dst_host_count = len(dst_host_count_feature_sessions)

        dst_host_srv_count_feature_sessions = list(
            filter(
                lambda x: is_same_dst_ip_and_srv(x, log),
                past_same_dst_port_100_sessions,
            )
        )

        dst_host_srv_count = len(dst_host_srv_count_feature_sessions)

        dst_host_same_src_port_rate = (
            (
                len(
                    list(
                        filter(
                            lambda x: is_same_src_port(x, log),
                            dst_host_count_feature_sessions,
                        )
                    )
                )
                / dst_host_count
            )
            if dst_host_count != 0
            else 0.0
        )

        dst_host_serror_rate = (
            (
                len(
                    list(
                        filter(
                            lambda x: is_syn_error(x),
                            dst_host_count_feature_sessions,
                        )
                    )
                )
                / dst_host_count
            )
            if dst_host_count != 0
            else 0.0
        )
        dst_host_srv_serror_rate = (
            (
                len(
                    list(
                        filter(
                            lambda x: is_syn_error(x),
                            dst_host_srv_count_feature_sessions,
                        )
                    )
                )
                / dst_host_srv_count
            )
            if dst_host_srv_count != 0
            else 0.0
        )

        flag = log.conn_state

        kyoto_feature = Kyoto2006Feature(
            unix_s,
            unix_ns,
            duration,
            service,
            source_bytes,
            destination_bytes,
            count,
            same_srv_rate,
            serror_rate,
            srv_serror_rate,
            dst_host_count,
            dst_host_srv_count,
            dst_host_same_src_port_rate,
            dst_host_serror_rate,
            dst_host_srv_serror_rate,
            flag,
        )
        features.append(kyoto_feature)
    write_to_csv(features, os.path.join(output_dir, "net_session.csv"))


if __name__ == "__main__":
    main()
