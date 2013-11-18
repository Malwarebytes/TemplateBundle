<?php

namespace Malwarebytes\TemplateBundle\Service;

use Symfony\Component\Finder\Finder;
use Twig_Environment,
    Twig_Loader_Filesystem;

class TemplateCatalog
{
    protected $twig;

    protected $templateData;

    public function __construct(Twig_Environment $twig)
    {
        $this->twig = $twig;
    }

    public function getTemplates()
    {
        $loader = $this->twig->getLoader();

        if(!$loader instanceof Twig_Loader_Filesystem) {
            return false;
        }

        $namespaces = $loader->getNamespaces();
        $templates = array();
        foreach($namespaces as $namespace) {
            $paths = $loader->getPaths($namespace);

            foreach($paths as $path) {
                $finder = new Finder();
                $finder->in($path)->name('*.*.twig');
                foreach($finder as $file) {
                    $localpath = substr($file->getPath(), strlen($path));
                    $templatename = "@$namespace$localpath/" . $file->getFilename();

                    if(strpos($templatename, '@MalwarebytesTemplate') === 0) {
                        var_dump($this->twig->parse($this->twig->tokenize($file->getContents())));
                    }

                    $templates[] = $templatename;
                }
            }
        }



        return $templates;
    }

    public function getTemplateData($template)
    {
        $loader = $this->twig->getLoader();
        $t = $loader->getSource($template);

        $tree = $this->twig->parse($this->twig->tokenize($t));

        $atts = array(
            'variables' => $tree->getAttribute('symbols'),
            'elements'  => $tree->getAttribute('elements'),
            'loops'     => $tree->getAttribute('loops'),
        );

        return array($template => $atts);
    }
}