<?php
/**
 * Created by PhpStorm.
 *
 * authenticate-bundle
 * (c) 2019 Craig Rayner <craig@craigrayner.com>
 *
 * User: craig
 * Date: 8/04/2019
 * Time: 08:49
 */
namespace Crayner\Authenticate\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Class InstallConfiguration
 * @package Crayner\Authenticate\Command
 */
class InstallConfiguration extends Command
{
    /**
     * @var string
     */
    protected static $defaultName = 'crayner:authenticate:install';

    /**
     * execute
     *
     * @param InputInterface $input
     * @param OutputInterface $output
     * @return int|null
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $kernel = $this->getApplication()->getKernel();
        $projectDir = $kernel->getProjectDir();


        if (! realpath($projectDir .'/config/packages/crayner_authenticate.yaml')) {
            copy($projectDir.'/vendor/crayner/authenticate-bundle/src/Resources/crayner_authenticate.yaml.dist', $projectDir .'/config/packages/crayner_authenticate.yaml');
        }

        return 0;
    }
}
