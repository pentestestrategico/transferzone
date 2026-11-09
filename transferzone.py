#!/usr/bin/env python3
"""
axfr_check.py - testa transferencia de zona DNS (AXFR) numa lista de hosts.

Uso:
    python3 transferzone.py -f osts.txt -t 20 --try-parent -o axfr_out

Requer: pip install dnspython
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.name
import dns.query
import dns.resolver
import dns.zone

POSITIVE_FILE = "axfr_positivos.txt"


def log(msg):
    print(msg, flush=True)


def get_ns(domain, resolver, timeout):
    try:
        ans = resolver.resolve(domain, "NS", lifetime=timeout, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.exception.DNSException):
        return []
    if ans.rrset is None:
        return []
    return [r.target.to_text(omit_final_dot=True) for r in ans]


def resolve_addr(host, resolver, timeout):
    ips = []
    for rtype in ("A", "AAAA"):
        try:
            ans = resolver.resolve(host, rtype, lifetime=timeout, raise_on_no_answer=False)
            if ans.rrset:
                ips.extend(r.address for r in ans)
        except dns.exception.DNSException:
            pass
    return ips


def attempt_axfr(zone, server, timeout, port):
    try:
        xfr = dns.query.xfr(server, zone, port=port, timeout=timeout,
                            lifetime=timeout * 3, relativize=True)
        z = dns.zone.from_xfr(xfr, relativize=True)
        return z, None
    except dns.query.TransferError as exc:
        return None, f"TransferError: {exc}"
    except dns.query.BadResponse as exc:
        return None, f"BadResponse: {exc}"
    except dns.exception.FormError as exc:
        return None, f"FormError: {exc}"
    except dns.exception.Timeout:
        return None, "timeout"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def check(domain, resolver, timeout, port, try_parent):
    result = {"domain": domain, "vulneravel": False, "ns": [], "tentativas": [],
              "registros": 0, "erro": None}

    zones = [domain]
    if try_parent:
        parts = domain.split(".")
        if len(parts) >= 3:
            zones.append(".".join(parts[-2:]))

    for zone in zones:
        ns_list = get_ns(zone, resolver, timeout)
        if not ns_list:
            continue
        result["ns"] = ns_list

        for ns in ns_list:
            alvos = [ns] + resolve_addr(ns, resolver, timeout)
            for alvo in alvos:
                z, err = attempt_axfr(zone, alvo, timeout, port)
                if z is None:
                    result["tentativas"].append(f"{alvo} -> {err}")
                    continue

                dump = z.to_text()
                total = sum(1 for _ in z.nodes)
                result.update(vulneravel=True, registros=total,
                              zone=zone, servidor=alvo, dump=dump)
                return result

    return result


def main():
    ap = argparse.ArgumentParser(description="Checa AXFR em lista de hosts")
    ap.add_argument("-f", "--file", required=True, help="arquivo com hosts, um por linha")
    ap.add_argument("-t", "--threads", type=int, default=15)
    ap.add_argument("-o", "--outdir", default="axfr_out")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--try-parent", action="store_true",
                    help="testa tambem o dominio pai de cada host")
    args = ap.parse_args()

    try:
        with open(args.file, encoding="utf-8") as fh:
            hosts = sorted({l.strip().lower() for l in fh if l.strip() and not l.startswith("#")})
    except OSError as exc:
        sys.exit(f"erro ao abrir {args.file}: {exc}")

    if not hosts:
        sys.exit("lista vazia")

    os.makedirs(args.outdir, exist_ok=True)
    resolver = dns.resolver.Resolver()
    resolver.lifetime = args.timeout

    log(f"[*] {len(hosts)} hosts | threads={args.threads} | timeout={args.timeout}s")

    positivos = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check, h, resolver, args.timeout, args.port,
                               args.try_parent): h for h in hosts}
        for i, fut in enumerate(as_completed(futures), 1):
            res = fut.result()
            dom = res["domain"]
            if res["vulneravel"]:
                positivos.append(res)
                path = os.path.join(args.outdir, f"axfr_{dom}.txt")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(res["dump"])
                log(f"[+] {dom} VULNERAVEL via {res['servidor']} "
                    f"({res['registros']} nos) -> {path}")
            else:
                motivo = res["tentativas"][0] if res["tentativas"] else "sem NS respondendo"
                log(f"[-] {dom} nao ({motivo})")

    if positivos:
        with open(os.path.join(args.outdir, POSITIVE_FILE), "w", encoding="utf-8") as fh:
            for r in positivos:
                fh.write(f"{r['domain']}\t{r['servidor']}\t{r['registros']}\n")
        with open(os.path.join(args.outdir, "axfr_resultado.json"), "w", encoding="utf-8") as fh:
            json.dump(positivos, fh, indent=2, ensure_ascii=False)

    log(f"\n[*] fim: {len(positivos)} positivos de {len(hosts)}")
    sys.exit(0 if positivos else 1)


if __name__ == "__main__":
    main()
