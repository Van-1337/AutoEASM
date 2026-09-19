# Rebuilds the Katana binary with jsluice enabled (-jsl can then parse endpoints from JS files). Official Windows builds skip this parser.
# AutoEASM never runs this script automatically — start it yourself if you want the extra JS crawling.

if (-not (Get-Command katana -ErrorAction SilentlyContinue)) {
    throw "Katana is not on PATH. Install it first, then run this script again."
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git is required to download Katana source."
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go is required to rebuild Katana."
}

# Katana prints its banner to stderr; cmd + Out-String keeps a single text blob for the regex
$versionText = cmd /c "katana -version 2>&1" | Out-String
if ($versionText -notmatch 'v\d+\.\d+\.\d+') {
    throw "Could not read Katana version from 'katana -version'."
}
$tag = $Matches[0]

$src = Join-Path $env:TEMP "katana-jsluice-build"
if (Test-Path $src) {
    Remove-Item -Recurse -Force $src
}

try {
    git clone --depth 1 --branch $tag https://github.com/projectdiscovery/katana.git $src
    if ($LASTEXITCODE -ne 0) { throw "git clone failed." }

    # This file is the Windows stub that does not register jsluice parsers
    $stub = Join-Path $src "pkg\engine\parser\parser_nojs.go"
    if (Test-Path $stub) {
        Remove-Item $stub
    }

    # Drop the build tag that excludes jsluice on Windows / 386
    $buildTag = '//go:build !(386 || windows)'
    foreach ($rel in @(
        "pkg\engine\parser\parser_generic.go",
        "pkg\utils\jsluice.go",
        "pkg\utils\jsluice_test.go"
    )) {
        $file = Join-Path $src $rel
        $text = [IO.File]::ReadAllText($file)
        $text = $text.Replace("$buildTag`r`n", "").Replace("$buildTag`n", "")
        [IO.File]::WriteAllText($file, $text)
    }

    $env:CGO_ENABLED = "0"
    go install -C $src ./cmd/katana
    if ($LASTEXITCODE -ne 0) { throw "go install failed." }

    Write-Host ""
    Write-Host "[+] Katana was rebuilt with jsluice. -jsl will now parse JavaScript files."
    Write-Host "    You can keep using AutoEASM as usual."
}
finally {
    if (Test-Path $src) {
        Remove-Item -Recurse -Force $src
    }
}
