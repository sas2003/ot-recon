from setuptools import setup, find_packages

setup(
    name="ot-recon",
    version="0.1",
    packages=find_packages(),
    install_requires=["pyyaml", "rich"],
    entry_points={
        'console_scripts': [
            'ot-recon=ot_recon.main:main'
        ]
    }
)