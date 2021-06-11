from setuptools import setup, find_packages

setup(
    name='certbot-dns-tencentcloud',
    version='1.1.0',
    author='Xiangyu Zhu',
    author_email='carsonzhu@tencent.com',
    description='Tencent Cloud DNS Authenticator plugin for Certbot',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/frefreak/certbot-dns-tencentcloud",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'certbot',
        'zope.interface',
    ],
    classifiers=[
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    entry_points={
        'certbot.plugins': [
            'dns-tencentcloud = certbot_dns_tencentcloud.certbot_tencentcloud_plugins:Authenticator',
        ],
    },
)
