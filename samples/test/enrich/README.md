# Testing Enrichment Feature

- This is just to test enrichment feature for present number of SBOMs in this folder. 
- By default, enrichment takes place for missing fields only. Like, enrichment of license, is for components missing license value or having value NOASSERTION or OTHER.
- We enriched license from centralized database, clearlydefined. If it return license values like NOASSERTION or OTHER, will skip from enrichment.
- Few other reasons of skipping enrichment are, missing of PURL IDs, or no license data found for component.

## Examples

1. Enrich SBOM by processing 100 components at a time.

```bash
sbomasm enrich --fields="license" samples/test/enrich/apache_airflow-sbom-2.8.0-python3.10.json    --output enriched-apache-sbom.cdx.json 


Total: 1750, Selected: 1562, Enriched: 1546, Skipped: 16, Failed: 0

```

1. Enrich SBOM, by processing 500 components at a time.

```bash
sbomasm enrich --fields="license" samples/test/enrich/apache_airflow-sbom-2.8.0-python3.10.json    --output enriched-apache-sbom.cdx.json  -c 500


Total: 1750, Selected: 1562, Enriched: 1546, Skipped: 16, Failed: 0
```

3. Enrich a SBOM, which contains total 13 components and all of them are missing license.

```bash
sbomasm enrich --fields="license" samples/test/enrich/dropwizard-missing-all-license.cdx.json    --output enriched-missing-license.cdx.json        


Total: 13, Selected: 12, Enriched: 9, Skipped: 3, Failed: 0

```

4. Let'e remove all PURL from SBOM and then try to enrich the SBOM

```bash
sbomasm rm  --field purl --scope component -a  samples/test/enrich/dropwizard-missing-all-license.cdx.json -o remove-dropwizard-all-purl.sbom.cdx.json
```

**NOTE**: All PURL has been removed and saved to `remove-dropwizard-all-purl.sbom.cdx.json` file. 

5. Now, try to Enrich an SBOM, for lacking PURLs

```bash
sbomasm enrich --fields="license" remove-dropwizard-all-purl.sbom.cdx.json    --output enriched-dropwizrd.sbom.cdx.json  

Total: 13, Selected: 0, Enriched: 0, Skipped: 0, Failed: 0

```

**NOTE**: It quickly fails, because for enrichment of SBOM requires PURL ID. If PURL ID is missing then enrichment will not proceed.

6. Enrich SBOM, forcefully for all components.

```bash
 sbomasm enrich --fields="license" samples/test/enrich/apache_airflow-sbom-2.8.0-python3.10.json    --output enriched-apache-sbom.cdx.json  -f  -c 500   


Total: 1750, Selected: 1750, Enriched: 1749, Skipped: 1, Failed: 0

```
