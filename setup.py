from setuptools import setup

setup(
	name='tomcat',
	packages=['tomcat'],
	include_package_data=True,
	install_requires=[
		'flask',
	]
)