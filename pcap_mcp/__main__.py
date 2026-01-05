import sys


def _main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in ("doctor", "--doctor"):
        from .doctor import run_doctor

        raise SystemExit(run_doctor())

    from .server import main

    main()


if __name__ == "__main__":
    _main()
