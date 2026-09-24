param(
    [string]$Repo = 'qingtianyu6/agentguard-v4',
    [Parameter(Mandatory = $true)][string]$Base
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$apiRoot = "https://api.github.com/repos/$Repo"
$token = gh auth token
if ($LASTEXITCODE -ne 0 -or -not $token) { throw 'GitHub CLI authentication is required' }
$headers = @{
    Authorization = "Bearer $token"
    'User-Agent' = 'AgentGuard-Codex'
    Accept = 'application/vnd.github+json'
}

function Invoke-GitHubApi($method, $path, $body = $null) {
    $params = @{ Uri = "$apiRoot/$path"; Headers = $headers; Method = $method }
    if ($null -ne $body) {
        $json = $body | ConvertTo-Json -Depth 30 -Compress
        $params.Body = [Text.Encoding]::UTF8.GetBytes($json)
        $params.ContentType = 'application/json'
    }
    Invoke-RestMethod @params
}

function Get-BlobBytes($sha) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = 'git'
    $info.Arguments = "cat-file blob $sha"
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $process = [System.Diagnostics.Process]::Start($info)
    $stream = New-Object System.IO.MemoryStream
    $process.StandardOutput.BaseStream.CopyTo($stream)
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw "git cat-file failed: $sha" }
    $stream.ToArray()
}

$remote = (Invoke-GitHubApi 'Get' 'git/ref/heads/main').object.sha
if ($remote -ne $Base) { throw "Remote main moved: $remote" }
$previousCommit = $Base
$previousTree = (Invoke-GitHubApi 'Get' "git/commits/$Base").tree.sha
$commits = @(git rev-list --reverse "$Base..HEAD")

foreach ($commit in $commits) {
    $items = @()
    foreach ($change in @(git diff-tree --no-commit-id --name-status -r $commit)) {
        $parts = $change.Split([char]9, 2)
        $status, $path = $parts[0], $parts[1]
        if ($status -eq 'D') {
            $items += @{ path = $path; mode = '100644'; type = 'blob'; sha = $null }
            continue
        }
        if ($status -notin @('A', 'M')) { throw "Unexpected change: $change" }
        $fields = (git ls-tree $commit -- $path).Split([char]32)
        if ($fields.Length -lt 3 -or $fields[1] -ne 'blob') { throw "Not a regular blob: $path" }
        $mode = $fields[0]
        $blobSha = $fields[2].Split([char]9)[0]
        $encoded = [Convert]::ToBase64String((Get-BlobBytes $blobSha))
        $uploaded = Invoke-GitHubApi 'Post' 'git/blobs' @{ content = $encoded; encoding = 'base64' }
        if ($uploaded.sha -ne $blobSha) { throw "Blob SHA mismatch: $path" }
        $items += @{ path = $path; mode = $mode; type = 'blob'; sha = $blobSha }
    }
    $tree = Invoke-GitHubApi 'Post' 'git/trees' @{ base_tree = $previousTree; tree = @($items) }
    $localTree = git rev-parse "$commit^{tree}"
    if ($tree.sha -ne $localTree) { throw "Tree SHA mismatch: $commit" }
    $message = (git show -s --format=%B $commit) -join "`n"
    $author = @{
        name = (git show -s --format=%an $commit)
        email = (git show -s --format=%ae $commit)
        date = (git show -s --format=%aI $commit)
    }
    $committer = @{
        name = (git show -s --format=%cn $commit)
        email = (git show -s --format=%ce $commit)
        date = (git show -s --format=%cI $commit)
    }
    $created = Invoke-GitHubApi 'Post' 'git/commits' @{
        message = $message
        tree = $localTree
        parents = @($previousCommit)
        author = $author
        committer = $committer
    }
    if ($created.sha -ne $commit) { throw "Commit SHA mismatch: local=$commit remote=$($created.sha)" }
    Write-Output "Verified $commit"
    $previousCommit, $previousTree = $commit, $localTree
}

$remote = (Invoke-GitHubApi 'Get' 'git/ref/heads/main').object.sha
if ($remote -ne $Base) { throw "Remote main moved before update: $remote" }
$updated = Invoke-GitHubApi 'Patch' 'git/refs/heads/main' @{ sha = $previousCommit; force = $false }
if ($updated.object.sha -ne $previousCommit) { throw 'Ref update returned a different SHA' }
Write-Output "Updated main to $previousCommit"
