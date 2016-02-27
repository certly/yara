## certly/yara

A YARA wrapper for PHP. Requires that a `yara` executable exist in your PATH or in a path specified.

```
$yara = new Certly\YARA\YARA();

$matches = $yara->match('abcdef', [
    '
        rule silent_banker : banker
        {
            meta:
                description = "An example rule."
        
            strings:
                $a = "abc"
        
            condition:
                $a
        }
    ',
]));

foreach ($matches as $match) {
    echo "Matched {$match['rule']}." . PHP_EOL;
    echo "Raw output: {$match['raw']}" . PHP_EOL;
}
```