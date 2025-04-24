# 🧠 AI Code Quality Analyzer

Upload `.rb`, `.py`, or `.js` files or GitHub repo URLs to detect potential security or quality issues. Includes suggestions + JSON export + charts.

## Features
- Static analysis for Ruby, Python, and JavaScript
- GitHub repo scan (clones and checks all files)
- Summary chart (powered by Chart.js)
- Download results as JSON
- Clean Sinatra-based interface

## To Run Locally

```bash
bundle install
ruby app.rb
```

## Open http://localhost:4567 in your browser.


Then:

```bash
git add README.md
git commit -m "Add README"
git push
```
