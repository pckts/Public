$resourceList = @(
    "resource1",
    "resource2"

)

foreach ($resourceName in $resourceList) {
    $resources = Get-AzResource -ResourceName $resourceName

    if ($resources.Count -eq 0) {
        Write-Host "No resources found with name $resourceName. Skipping..."
        continue
    }

    foreach ($resource in $resources) {
        $tag = @{
            "TAGNAME" = "VALUE"
        }

        $retryCount = 0
        while ($retryCount -lt 2) {
            try {
                Update-AzTag -ResourceId $resource.ResourceId -Tag $tag -Operation Merge
                break
            } catch {
                Write-Host "Failed to set tag - $($resource.ResourceId)..."
                $retryCount++
                continue
            }
        }
    }
}
