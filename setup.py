import re
from pathlib import Path

from setuptools import setup, find_packages

# Read (not import) the version so setup never needs the package's
# dependencies installed yet.
_version = re.search(
    r'__version__\s*=\s*"([^"]+)"',
    (Path(__file__).parent / "ot_recon" / "__init__.py").read_text(),
).group(1)

setup(
    name="ot-recon",
    version=_version,
    packages=find_packages(),
    install_requires=["pyyaml", "rich"],
    extras_require={
        "dev": ["pytest", "pytest-cov"],
        # wxPython has no universal prebuilt wheel - on Debian/Ubuntu,
        # install it via apt (python3-wxgtk4.0) rather than letting pip
        # try to compile it; see README for details.
        "gui": ["gooey"],
        # Only needed if cve.live_lookup is enabled (NVD API calls).
        "cve-live": ["requests"],
    },
    entry_points={
        'console_scripts': [
            'ot-recon=ot_recon.main:main',
            'ot-recon-gui=ot_recon.gui:gui_main',
        ]
    }
)
