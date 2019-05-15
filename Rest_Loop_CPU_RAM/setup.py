from setuptools import setup, find_packages
deps = ['paramiko','matplotlib','numpy', 'requests',]

setup(
    name='rest_loop_loading',
    version='2.0.7',
    packages=find_packages(),
    python_requires='>=3.6',
    install_requires=deps,
    entry_points={'console_scripts': ['memory_tester.py = rest_loop_loading.script.memory_tester:main']}
)
