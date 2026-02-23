"""src/cli.py - command line interface for bima
"""
import argparse
import sys


# ---------------- TEST COMMAND ----------------
def cmd_test(args):
    from .classifier import classify_url

    url = args.url.strip()
    print("\n=== RESULT ===")
    print("URL:", url)

    result = classify_url(url)

    crawler = result.get("crawler", {})
    if crawler.get("status") in ("error", "blocked"):
        print("Crawler:", crawler.get("status").upper())
    else:
        print(
            "Crawler: OK (rules_label=%s, rules_score=%s)"
            % (crawler.get("rules_label"), crawler.get("rules_score"))
        )

    ml = result.get("ml")
    if ml:
        label = "PHISHING" if ml.get("label") == 1 else "LEGIT"
        print("ML Label:", label)
        print("Probability:", round(float(ml.get("probability", 0.0)), 4))
        print("Confidence:", f"{ml.get('confidence', 0)}%")
    else:
        print("ML: not invoked")

    print("Final stage:", result.get("final_stage"))
    print("Final label:", result.get("final_label"))
    print("Final score:", result.get("final_score"))
    print("================\n")


# ---------------- TRAIN COMMAND ----------------
def cmd_train(args):
    from .model import train_model, DATASETS_DIR, MODEL_PATH, META_PATH
    ds = getattr(args, "dataset", None)
    calibrate = bool(getattr(args, "calibrate", False))
    balance = not bool(getattr(args, "no_balance", False))

    # If no explicit dataset provided, show which CSVs will be auto-loaded.
    if ds is None:
        print("Auto-detecting datasets in:", DATASETS_DIR)
        csvs = sorted(DATASETS_DIR.glob("*.csv"))
        if csvs:
            print("Found dataset files:")
            for p in csvs:
                print(" -", p.name)
        else:
            print("[WARN] No CSV files found in datasets/ directory.")

    print("Starting training...")

    if args.force:
        try:
            if MODEL_PATH.exists():
                print("[INFO] Removing old model:", MODEL_PATH)
                MODEL_PATH.unlink()
            if META_PATH.exists():
                META_PATH.unlink()
        except Exception as e:
            print("[WARN] Failed to remove old model/meta:", e)

    train_model(
        dataset_path=ds,
        calibrate=calibrate,
        balance=balance,
        test_size=args.test_size,
        use_page_features=getattr(args, "use_crawler", False),
        checkpoint_path=getattr(args, "checkpoint", None),
        resume=getattr(args, "resume", False),
    )

    print("\n[OK] Training finished successfully.\n")


# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(
        prog="bima",
        description="BIMA - Phishing URL Detector",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # -------- test --------
    p_test = sub.add_parser("test", help="Test a single URL")
    p_test.add_argument("url", help="URL to classify")
    p_test.add_argument("--screenshot", action="store_true", help="Capture a screenshot (requires selenium/webdriver)")
    p_test.add_argument("--debug", action="store_true")
    p_test.set_defaults(func=cmd_test)
    
    # -------- train --------
    p_train = sub.add_parser("train", help="Train ML model")
    
    p_train.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Path to CSV dataset (default: auto-detect in datasets/)",
    )

    p_train.add_argument(
        "--calibrate",
        action="store_true",
        help="Enable probability calibration (slower, more accurate)",
    )

    p_train.add_argument(
        "--no-balance",
        action="store_true",
        help="Disable class balancing",
    )

    p_train.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test split size (default: 0.2)",
    )

    p_train.add_argument(
        "--use-crawler",
        action="store_true",
        help="Fetch pages via crawler to include page features (slow)",
    )

    p_train.add_argument(
        "--checkpoint",
        type=str,
        default=None,
        help="Path to save/load preprocessing checkpoint (default: datasets/feature_cache.npz)",
    )

    p_train.add_argument(
        "--resume",
        action="store_true",
        help="Resume from checkpoint if it exists (skip feature extraction)",
    )


    p_train.add_argument(
        "--force",
        action="store_true",
        help="Force retrain (delete existing model first)",
    )

    p_train.set_defaults(func=cmd_train)

    args = parser.parse_args()

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[ABORTED] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print("\n[ERROR]", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
# src/cli.py
import argparse
import sys


# ---------------- TEST COMMAND ----------------
def cmd_test(args):
    from .classifier import classify_url
    import base64
    import os

    url = args.url.strip()
    print("\n=== RESULT ===")
    print("URL:", url)

    result = classify_url(url, capture_screenshot=getattr(args, "screenshot", False))

    crawler = result.get("crawler", {})
    if crawler.get("status") in ("error", "blocked"):
        print("Crawler:", crawler.get("status").upper())
    else:
        print(
            "Crawler: OK (rules_label=%s, rules_score=%s)"
            % (crawler.get("rules_label"), crawler.get("rules_score"))
        )

    ml = result.get("ml")
    if ml:
        label = "PHISHING" if ml.get("label") == 1 else "LEGIT"
        print("ML Label:", label)
        print("Probability:", round(float(ml.get("probability", 0.0)), 4))
        print("Confidence:", f"{ml.get('confidence', 0)}%")
    else:
        print("ML: not invoked")

    print("Final stage:", result.get("final_stage"))
    print("Final label:", result.get("final_label"))
    print("Final score:", result.get("final_score"))
    # if screenshot data is present, write it to disk for inspection
    crawler_info = result.get("crawler", {}) or {}
    b64 = crawler_info.get("screenshot")
    if b64:
        try:
            # data URL may start with data:image/png;base64,
            if b64.startswith("data:"):
                b64data = b64.split(",", 1)[1]
            else:
                b64data = b64
            out_path = os.path.abspath("bima_screenshot.png")
            with open(out_path, "wb") as fh:
                fh.write(base64.b64decode(b64data))
            print("Saved screenshot to:", out_path)
        except Exception as e:
            print("[WARN] Failed to save screenshot:", e)

    print("================\n")


# ---------------- TRAIN COMMAND ----------------
def cmd_train(args):
    from .model import train_model, DATASETS_DIR, MODEL_PATH, META_PATH
    ds = getattr(args, "dataset", None)
    calibrate = bool(getattr(args, "calibrate", False))
    balance = not bool(getattr(args, "no_balance", False))

    # If no explicit dataset provided, show which CSVs will be auto-loaded.
    if ds is None:
        print("Auto-detecting datasets in:", DATASETS_DIR)
        csvs = sorted(DATASETS_DIR.glob("*.csv"))
        if csvs:
            print("Found dataset files:")
            for p in csvs:
                print(" -", p.name)
        else:
            print("[WARN] No CSV files found in datasets/ directory.")

    print("Starting training...")

    if args.force:
        try:
            if MODEL_PATH.exists():
                print("[INFO] Removing old model:", MODEL_PATH)
                MODEL_PATH.unlink()
            if META_PATH.exists():
                META_PATH.unlink()
        except Exception as e:
            print("[WARN] Failed to remove old model/meta:", e)

    train_model(
        dataset_path=ds,
        calibrate=calibrate,
        balance=balance,
        test_size=args.test_size,
        use_page_features=getattr(args, "use_crawler", False),
        checkpoint_path=getattr(args, "checkpoint", None),
        resume=getattr(args, "resume", False),
    )

    print("\n[OK] Training finished successfully.\n")


# ---------------- MAIN ----------------
def main():
    parser = argparse.ArgumentParser(
        prog="bima",
        description="BIMA - Phishing URL Detector",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # -------- test --------
    p_test = sub.add_parser("test", help="Test a single URL")
    p_test.add_argument("url", help="URL to classify")
    p_test.add_argument("--debug", action="store_true")
    p_test.set_defaults(func=cmd_test)
    
    # -------- train --------
    p_train = sub.add_parser("train", help="Train ML model")
    
    p_train.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Path to CSV dataset (default: auto-detect in datasets/)",
    )

    p_train.add_argument(
        "--calibrate",
        action="store_true",
        help="Enable probability calibration (slower, more accurate)",
    )

    p_train.add_argument(
        "--no-balance",
        action="store_true",
        help="Disable class balancing",
    )

    p_train.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test split size (default: 0.2)",
    )

    p_train.add_argument(
        "--use-crawler",
        action="store_true",
        help="Fetch pages via crawler to include page features (slow)",
    )

    p_train.add_argument(
        "--force",
        action="store_true",
        help="Force retrain (delete existing model first)",
    )

    p_train.set_defaults(func=cmd_train)

    args = parser.parse_args()

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[ABORTED] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print("\n[ERROR]", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
