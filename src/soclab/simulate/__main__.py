"""CLI: python -m soclab.simulate --out data/generated --seed 42"""

import argparse

from soclab.simulate.generator import generate, write_dataset


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="python -m soclab.simulate", description="Generate labelled SOC lab logs."
    )
    ap.add_argument("--out", default="data/generated", help="output directory")
    ap.add_argument("--seed", type=int, default=42, help="same seed = same dataset")
    ap.add_argument("--hours", type=int, default=24)
    args = ap.parse_args()

    ds = generate(seed=args.seed, hours=args.hours)
    paths = write_dataset(ds, args.out)
    print(f"auth.log: {len(ds.auth_lines)} lines -> {paths['auth']}")
    print(f"ufw.log:  {len(ds.ufw_lines)} lines -> {paths['ufw']}")
    for gt in ds.ground_truth:
        print(f"planted {gt.scenario:<15} {gt.mitre_technique:<10} from {gt.source_ip}")


if __name__ == "__main__":
    main()
