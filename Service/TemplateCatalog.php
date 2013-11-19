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
/*
                    if(strpos($templatename, '@MalwarebytesTemplate') === 0) {
                        var_dump($this->twig->parse($this->twig->tokenize($file->getContents())));
                    }*/

                    $templates[] = $templatename;
                }
            }
        }

        return $templates;
    }

    public function getInfo($template)
    {
        $loader = $this->twig->getLoader();
        $t = $loader->getSource($template);

        $tree = $this->twig->parse($this->twig->tokenize($t));

        $variables = $tree->getAttribute('symbols');
        $elements = $tree->getAttribute('elements');
        $expressions = array();

        foreach($variables as $variable) {
            $expressions[$variable] = array();
        }

        foreach($elements as $element) {
            $pieces = explode('.', $element);
            $head = array_shift($pieces);
            $target = &$expressions[$head];
            while(count($pieces) > 0) {
                $piece = array_shift($pieces);
                $target[$piece] = array();
                $target = &$target[$piece];
            }
        }

        $includes = $tree->getAttribute('includes');
        foreach($includes as &$include) {
            $include['templates'] = array_map(
                function($t) use ($template) { return $this->normalizeTemplateName($template, $t); },
                $include['templates']
            );
        }

        $atts = array(
            'expressions'   => $expressions,
            'loops'         => $tree->getAttribute('loops'),
            'parent'        => $tree->hasAttribute('parent')
                    ? $this->normalizeTemplateName($template, $tree->getAttribute('parent'))
                    : null,
            'includes'      => $includes,
            'name'          => $template,
        );

        return $atts;
    }

    protected function normalizeTemplateName($source, $name)
    {
        if(strpos($name, '@') === 0) {
            return $name;
        }

        if(strpos($name, ':') === false) {
            return substr($source, 0, strrpos($source, '/') + 1) . $name;
        }

        $pieces = explode(':', $name);

        $namespace = array_shift($pieces);
        if($namespace === '') {
            $namespace = '__main__';
        } else if(strpos($namespace, 'Bundle') !== false) {
            $namespace = substr($namespace, 0, strpos($namespace, 'Bundle'));
        }

        $dir = array_shift($pieces);
        $name = array_shift($pieces);

        return '@' . join('/', array($namespace, $dir, $name));
    }
}