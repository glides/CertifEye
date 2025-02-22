<#
.SYNOPSIS
    Exports Certificate Authority logs to a CSV file with detailed information.

.PARAMETER OutputCsv
    The path to the output CSV file. Defaults to 'C:\CA\exported_ca_logs.csv'.

.EXAMPLE
    .\Export-CALogs.ps1 -OutputCsv "C:\Logs\export.csv"
#>

param(
    [string]$OutputCsv = "C:\CA\exported_ca_logs.csv"
)

try {
    $outputDir = Split-Path $OutputCsv -Parent
    if (!(Test-Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
    }

    # Yummy, variables
    $certDataList = @()
    $progressCounter = 0

    Write-Host "Retrieving issued certificates Request IDs..."
    $issuedCertsOutput = certutil -view -restrict "Disposition=20" -out "RequestID"

    # Parse the Request IDs from the output
    $requestIDs = @()
    foreach ($line in $issuedCertsOutput) {
        if ($line -match "^\s*Issued Request ID:.*\((\d+)\)") {
            $requestID = $matches[1]
            $requestIDs += $requestID
        }
    }

    if ($requestIDs.Count -eq 0) {
        Write-Error "No issued certificates found."
        exit
    }

    $totalRequests = $requestIDs.Count
    Write-Host "Found $totalRequests issued certificates."

    # Process each certificate
    foreach ($requestID in $requestIDs) {
        $progressCounter++

        # Calculate percentage
        $percentage = ($progressCounter / $totalRequests) * 100

        # Update the progress bar
        Write-Progress -Activity "Processing Certificates" -Status "Processing Request ID $requestID" -PercentComplete $percentage

        try {
            # Use certutil -view to get the certificate details
            $certDetails = certutil -view -restrict "RequestID=$requestID"

            # Initialize data fields
            $subjectName = $null
            $commonName = $null
            $sanList = @()
            $ekuList = @()
            $validFrom = $null
            $validTo = $null
            $serialNumber = $null
            $requesterName = $null
            $template = $null
            $requestTime = $null
            $disposition = $null

            # Flags for capturing multi-line values
            $captureSANs = $false
            $captureEKUs = $false
            $captureDisposition = $false
            $dispositionLines = @()
            $templatePending = $false

            foreach ($line in $certDetails) {
                if ($captureDisposition) {
                    $dispositionLines += $line
                    if ($line -match '.*"$') {
                        # End of multi-line disposition message
                        $captureDisposition = $false
                        $disposition = ($dispositionLines -join "`n").Trim('"')
                        $dispositionLines = @()
                    }
                    continue
                }

                if ($templatePending) {
                    # Capture the template name from the next line
                    $template = $line.Trim()
                    $templatePending = $false
                    continue
                }

                if ($line -match '^\s*Issued Distinguished Name:\s*"(.*)"$') {
                    $subjectName = $matches[1].Trim()
                } elseif ($line -match '^\s*Issued Common Name:\s*"(.*)"$') {
                    $commonName = $matches[1].Trim()
                } elseif ($line -match '^\s*Requester Name:\s*"(.*)"$') {
                    $requesterName = $matches[1].Trim()
                } elseif ($line -match '^\s*Certificate Effective Date:\s*(.+)$') {
                    $validFrom = [datetime]::Parse($matches[1].Trim())
                } elseif ($line -match '^\s*Certificate Expiration Date:\s*(.+)$') {
                    $validTo = [datetime]::Parse($matches[1].Trim())
                } elseif ($line -match '^\s*Serial Number:\s*(.+)$') {
                    $serialNumber = $matches[1].Trim()
                } elseif ($line -match '^\s*Template=(.+)$') {
                    $template = $matches[1].Trim()
                } elseif ($line -match '^\s*Certificate Template Name \(Certificate Type\)') {
                    $templatePending = $true
                } elseif ($line -match '^\s*Request Submission Date:\s*(.+)$') {
                    $requestTime = [datetime]::Parse($matches[1].Trim())
                } elseif ($line -match '^\s*Request Disposition Message:\s*(.*)$') {
                    $dispositionLine = $matches[1].Trim()
                    if ($dispositionLine -match '^"(.*)"$') {
                        # Single line disposition
                        $disposition = $matches[1].Trim('"')
                    } elseif ($dispositionLine -match '^"(.*)$') {
                        # Start of multi-line disposition
                        $captureDisposition = $true
                        $dispositionLines = @($dispositionLine)
                        if ($dispositionLine -match '.*"$') {
                            # Handle case where start and end quotes are on the same line
                            $captureDisposition = $false
                            $disposition = ($dispositionLines -join "`n").Trim('"')
                            $dispositionLines = @()
                        }
                    } else {
                        $disposition = $dispositionLine
                    }
                } elseif ($line -match '^\s*Subject Alternative Name') {
                    $captureSANs = $true
                    continue
                } elseif ($line -match '^\s*Enhanced Key Usage') {
                    $captureEKUs = $true
                    continue
                } elseif ($captureSANs -and ($line -match "^\s*$")) {
                    $captureSANs = $false
                } elseif ($captureEKUs -and ($line -match "^\s*$")) {
                    $captureEKUs = $false
                }

                if ($captureSANs -and $line -notmatch '^\s*Subject Alternative Name') {
                    $sanList += $line.Trim()
                } elseif ($captureEKUs -and $line -notmatch '^\s*Enhanced Key Usage') {
                    $ekuList += $line.Trim()
                }
            }

            $sanList = $sanList -join ", "
            $ekuList = $ekuList -join ", "

            # Prepare data object
            $certData = [PSCustomObject]@{
                RequestID                   = $requestID
                CertificateIssuedCommonName = $commonName
                CertificateSubject          = $subjectName
                CertificateSANs             = $sanList
                EnhancedKeyUsage            = $ekuList
                CertificateValidityStart    = $validFrom
                CertificateValidityEnd      = $validTo
                SerialNumber                = $serialNumber
                RequesterName               = $requesterName
                CertificateTemplate         = $template
                RequestSubmissionTime       = $requestTime
                RequestDisposition          = $disposition
            }

            # Identify missing fields, excluding EnhancedKeyUsage and CertificateSANs
            $fieldsToCheck = @(
                "CertificateIssuedCommonName",
                "CertificateSubject",
                "CertificateValidityStart",
                "CertificateValidityEnd",
                "SerialNumber",
                "RequesterName",
                "CertificateTemplate",
                "RequestSubmissionTime",
                "RequestDisposition"
            )

            $missingFields = @()
            foreach ($field in $fieldsToCheck) {
                if (-not $certData.$field) {
                    $missingFields += $field
                }
            }

            if ($missingFields.Count -gt 0) {
                $fieldsList = $missingFields -join ", "
                Write-Warning "Certificate with Request ID $requestID is missing the following fields: $fieldsList"
            }

            # Add the certificate data to the list
            $certDataList += $certData

        } catch {
            Write-Warning "Failed to process Request ID $requestID : $_"
        }
    }

    # Complete the progress bar
    Write-Progress -Activity "Processing Certificates" -Completed

    # Export data to CSV
    $certDataList | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

    Write-Host "Export completed. Logs saved to $OutputCsv"

} catch {
    Write-Error "An error occurred: $_"
}
