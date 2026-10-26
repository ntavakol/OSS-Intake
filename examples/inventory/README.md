# Sample: package inventory

`packages.sample.csv` is a made-up inventory of public packages, as a package repository export or a spreadsheet
might list them, with an owner and system for each. Some versions are deliberately old or compromised so the
report has something to show.

```bash
cp examples/inventory/packages.sample.csv /tmp/packages.csv
oss-intake --path /tmp/packages.csv --out /tmp/inventory-report
```

The file is named `.sample.csv` only for clarity; any `.csv` file is read as an inventory. Owners and systems are
fictional.
