===================
 Alnitak Changelog
===================

0.2
===

* Many bugfixes.
* Improved the API schemes functionality.
* Custom command-line parser.
* Custom logger.
* Changed command-line behaviour.
* Added printing of TLSA records.

0.1.7
=====

* Fixed bug whereby a non-directory in the live directory would make a dane
  directory named after that file and then cause the program to fail.

0.1.6
=====

* PATH parameter that is set if calling the binary API scheme fixed.

0.1.5
=====

* Fixed setup.py settings so long description read on PyPI properly.
* Markdown changed to ReStructuredText.

0.1.4
=====

* Fixed missing package info and misconfigured info for PyPI.
* Markdown mistakes in README.md fixed.

0.1.3
=====

* Fixed the package homepage in v0.1.2 which still did not work.

0.1.2
=====

* Changed package homepage in the setup.py script.

0.1.1
=====

* Made the logging code more robust (perhaps overkill...).
* Added tests to check the logging code works as expected.
* Modified the locking code to use fcntl.lockf.
* Added and/or fixed doctrings.
