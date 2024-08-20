$PrimarySMTP = "@domain1.tld"
$AliasSMTP = "@domain2.tld"

$mailboxes = get-content -path $home\desktop\mailboxes.txt
foreach ($mailbox in $mailboxes)
{
    $CurrentAlias = $mailbox+$PrimarySMTP
    $NewAlias = $mailbox+$AliasSMTP
    get-mailbox -Identity $CurrentAlias | set-mailbox -EmailAddresses @{Add="smtp:$NewAlias"}
}
