from setuptools import setup, find_packages

setup(
    name='bleach',
    version='1.2.2',
    description='An easy whitelist-based HTML-sanitizing tool. Supermassive.io version',
    long_description=open('README.rst').read(),
    author='James Socol + Josiah Young',
    author_email='me@jamessocol.com',
    url='https://github.com/quadrivium33/bleach',
    license='BSD',
    packages=find_packages(),
    include_package_data=True,
    package_data={'': ['README.rst']},
    zip_safe=False,
    install_requires=['html5lib==0.95'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Environment :: Web Environment :: Mozilla',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
