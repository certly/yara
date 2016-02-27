<?php
namespace Certly\YARA;

use Symfony\Component\Process\Process;

class YARA
{
    /**
     * The path, ending in a forward slash, to an executable named 'yara'.
     *
     * @var string
     */
    protected $path;

    /**
     * Any options that should be passed to YARA.
     *
     * @var array
     */
    protected $options;

    /**
     * Create a new YARA.
     *
     * @return void
     */
    public function __construct(array $options = ['-w'], string $path = '')
    {
        $this->path = $path;
        $this->options = $options;
    }

    /**
     * Match an $item against an array of $rules.
     *
     * @param  array $rules
     * @param  string $item
     * @return array
     */
    public function match(array $rules, string $item): array
    {
        $ruleFile = $this->tempFile();
        $rules = implode(PHP_EOL, $rules);

        $itemFile = $this->tempFile();

        file_put_contents($ruleFile, $rules);
        file_put_contents($itemFile, $item);

        $output = $this->run([
            $ruleFile,
            $itemFile,
        ], $this->options);

        unlink($ruleFile);
        unlink($itemFile);

        $output = trim($output);

        if (empty($output)) {
            return [];
        }

        return $this->parseOutput($output);
    }

    /**
     * Run YARA with $options and $arguments.
     *
     * @param array $arguments
     * @param array $options
     * @return string
     */
    protected function run(array $arguments, array $options = []): string
    {
        $process = new Process($this->path.'yara '.implode($options, ' ').' '.implode($arguments, ' '));

        $process->mustRun();

        return $process->getOutput();
    }

    /**
     * Get a temporary file name to use when storing rules.
     *
     * @return string
     */
    protected function tempFile(): string
    {
        return tempnam(sys_get_temp_dir(), 'yara');
    }

    /**
     * Parse the output of a successful YARA command.
     *
     * @param string $output
     * @return array
     */
    protected function parseOutput(string $output): array
    {
        $matches = [];

        foreach (explode(PHP_EOL, $output) as $line) {
            $line = explode(' ', $line);

            $matches[] = [
                'rule' => $line[0],
                'raw' => $line,
            ];
        }

        return $matches;
    }
}
