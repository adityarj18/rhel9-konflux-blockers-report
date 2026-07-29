# RHEL 9 Konflux blockers report

Static snapshot of blocked packages from the RHEL 9 Konflux migration spreadsheet.

- Source sheet: [RHEL 9 Konflux migration](https://docs.google.com/spreadsheets/d/1MJhmkOFgbSjuvuO9f8v5DDWiuxiMTGPOhVOHII67-5o)
- Parent Jira: [KFLUXMIG-1166](https://redhat.atlassian.net/browse/KFLUXMIG-1166)

Open the GitHub Pages site (Settings → Pages) or open `index.html` after cloning.

**Access:** Public GitHub Pages — anyone with the URL can view the report: https://adityarj18.github.io/rhel9-konflux-blockers-report/

## Auto-refresh

`index.html` and `data/dashboard.json` are regenerated automatically every day
(~09:40 IST / 04:10 UTC) by [`.github/workflows/refresh-report.yml`](.github/workflows/refresh-report.yml),
and can also be triggered manually from the Actions tab (**Run workflow**).
The workflow runs `scripts/build_report.py`, which:

- downloads the tracking spreadsheet from Google Drive via a service account
  (`GOOGLE_SERVICE_ACCOUNT_JSON` repo secret),
- enriches every blocker key with live Jira status/assignee/labels
  (`JIRA_EMAIL` + `JIRA_API_TOKEN` repo secrets), and
- commits the refreshed `index.html` / `data/dashboard.json` back to `main`
  only when something changed.

To run it locally instead:

```bash
scripts/run_local.sh /path/to/RHEL9-Konflux-migration.xlsx
```

Jira enrichment is optional locally — export `JIRA_EMAIL`/`JIRA_API_TOKEN`
(and optionally `JIRA_BASE`) first if you want live status; otherwise the
report is built from the spreadsheet alone with blocker status `Unknown`.
