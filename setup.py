import setuptools


if __name__ == "__main__":
    with open("README.md", "r") as fh:
        long_description = fh.read()

    setuptools.setup(
        name="gtirb-live-register-analysis",
        version="0.0.7",
        author="Fangzheng Lin",
        author_email="csl@lunlimited.net",
        description="Utilities for dealing with live register analysis in GTIRB functions",
        packages=setuptools.find_packages(),
        package_data={"gtirb_live_register_analysis": ["py.typed"]},
        install_requires=["gtirb"],
        classifiers=["Programming Language :: Python :: 3"],
        long_description=long_description,
        long_description_content_type="text/markdown",
        url="https://github.com/lin-toto/gtirb-live-register-analysis",
        license="GPLv3",
    )
