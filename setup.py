from distutils import setup, find_packages

setup(
    name="Mrzy-Client-Library",
    version="0.0.1",
    description="每日交作业客户端库",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/xiaoxi-ij478/mrzy_client_lib",
    author="xiaoxi-ij478",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Topic :: Education",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3 :: Only",
    ],
    packages=find_packages(),
    python_requires=">=3.7, <4",
    install_requires=["qrcode"]
)
