from setuptools import setup, find_packages

setup(
    name="Passholder",
    version="1.0",

    packages=find_packages('src') + ['twisted.plugins'],
    package_dir={
        '': 'src',
        },
    install_requires=[
        'twisted',
        'pyOpenSSL',
        'scrypt',
        'txredisapi',
        ],
    author="Konstantin Misyutin",
    author_email="ikeeip@gmail.com",
    description="Secure password storage service",
    keywords="scrypt ssl password storage service",
    url="https://github.com/ikeeip/passholder",
    )
