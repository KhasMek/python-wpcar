#/usr/bin/python3

# TODO: need to set up the datadir

from setuptools import find_packages, setup

setup(
    name='wpcar',
    version='0.5',
    description='Wireless Packet Capture Auditing and Reporting.',
    url='https://github.com/KhasMek/python-wpcar',
    author='Khas Mek',
    include_package_data=True,
    install_requires=[
        'colorama',
        'pyshark',
        'pyyaml',
        'tqdm',
        'xlsxwriter'
    ],
    packages=find_packages(),
    entry_points={
        'console_scripts': [
        'wpcar = wpcar.wpcar:main'
        ]
    },
)
