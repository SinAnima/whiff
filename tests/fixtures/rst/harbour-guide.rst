===============
Saltmere Harbour
===============

----------------------------
A guide for visiting sailors
----------------------------

:Author: Ada Quayside
:Date: 2025-11-05
:Version: 1.4
:Copyright: 2025 Saltmere Harbour Board

.. meta::
   :description: Moorings, tides and services at Saltmere Harbour.
   :keywords: harbour, moorings, tides

Arriving
========

Call the harbour master on VHF channel 12 before entering. See the
`tide tables <https://tides.example.org/saltmere>`_ and the
:ref:`moorings` section.

.. image:: images/approach.png
   :alt: The approach to Saltmere

Moorings
--------

.. _moorings:

Visitor moorings are on the east pontoon. [#fees]_

.. list-table:: Mooring fees
   :header-rows: 1

   * - Length
     - Per night
   * - Under 10 m
     - 18.00

Checking the tide::

   tide --port saltmere --days 3

.. code-block:: python

   from tides import forecast
   print(forecast("saltmere"))

.. include:: services.rst

.. [#fees] Fees are reviewed every April.

.. _board: https://board.example.org/
