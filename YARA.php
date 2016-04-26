<?hh

namespace Certly\YARA;

use Symfony\Component\Process\Process;

class YARA
{
    /**
     * The path, ending in a forward slash, to an executable named 'yara'.
     *
     * @var string
     */
    private $path;

    /**
     * Any options that should be passed to YARA.
     *
     * @var array
     */
    private $options;

    /**
     * Create a new YARA.
     *
     * @return void
     */
    public function __construct(array $options = ['-w'], string $path = '')
    {
        $this->setOptions($options);
        $this->setPath($path);
    }

    /**
     * Match an $item against an array of $rules.
     *
     * @param array  $rules
     * @param string $item
     *
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
        ], $this->getOptions());

        unlink($ruleFile);
        unlink($itemFile);

        $output = trim($output);

        if (empty($output)) {
            return [];
        }

        return $this->parseOutput($output);
    }

    /**
     * Retrieve the configured options.
     *
     * @return array
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Overwrite the configured options with an array.
     *
     * @param array $options
     *
     * @return array
     */
    public function setOptions(array $options): array
    {
        foreach ($options as $index => $option) {
            $options[$index] = escapeshellarg($option);
        }

        return $this->options = $options;
    }

    /**
     * Add an option to the configured options.
     *
     * @param string $option
     *
     * @return array
     */
    public function setOption(string $option): array
    {
        return $this->setOptions(array_merge($this->options, [$option]));
    }

    /**
     * Get the path used when calling YARA.
     *
     * @return string
     */
    public function getPath(): string
    {
        return $this->path;
    }

    /**
     * Set the path used when calling YARA.
     *
     * @param string $path
     *
     * @return string
     */
    public function setPath(string $path): string
    {
        return $this->path = escapeshellarg($path);
    }

    /**
     * Run YARA with $options and $arguments.
     *
     * @param array $arguments
     * @param array $options
     *
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
     *
     * @return array
     */
    protected function parseOutput(string $output): array
    {
        $matches = [];

        foreach (explode(PHP_EOL, $output) as $line) {
            $line = explode(' ', $line);

            $matches[] = [
                'rule' => $line[0],
                'raw'  => $line,
            ];
        }

        return $matches;
    }
}
