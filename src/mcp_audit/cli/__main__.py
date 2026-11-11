"""Enable ``python -m mcp_audit.cli`` (and the PyInstaller binaries' entry).

Goes through :func:`mcp_audit._entry.main` so ``run`` takes the lean path in
the frozen binary too.
"""

from mcp_audit._entry import main

if __name__ == "__main__":
    main()
