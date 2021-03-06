import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
     name='wsid-basic',  
     version='0.1.0',
     scripts=[] ,
     author="Hleb Rubanau",
     author_email="contact@rubanau.com",
     description="Basic WSID libraries",
     long_description=long_description,
     long_description_content_type="text/markdown",
     url="https://github.com/hleb-rubanau/wsid-basic",
     packages=['wsid.basic'],
     install_requires=[
        'PyNaCl', 
        'cachetools',
        'requests'
     ],
     license="MIT",
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
     ],
)

