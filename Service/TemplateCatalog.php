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
                    $templates[] = $templatename;
                }
            }
        }

        return $templates;
    }

    public function getInfo($template)
    {
        $info = $this->getLocalInfo($template);
        $info = $this->getParentInfo($template, $info);
        $info = $this->getIncludeInfo($template, $info);


        return $info;
    }

    protected function getLocalInfo($template)
    {
        $loader = $this->twig->getLoader();
        $t = $loader->getSource($template);

        $tree = $this->twig->parse($this->twig->tokenize($t));

        $variables = $tree->getAttribute('symbols');
        $elements = $tree->getAttribute('elements');

        $expressions = $this->buildExpressions($variables, $elements);
        $expressions = $this->addLoopsToExpressions($tree->getAttribute('loops'), $expressions);

        $includes = $tree->getAttribute('includes');
        foreach($includes as &$include) {
            $include['templates'] = array_map(
                function($t) use ($template) { return $this->normalizeTemplateName($template, $t); },
                $include['templates']
            );
        }

        $expressions = $this->addForwards($includes, $expressions);

        $atts = array(
            'expressions'   => $expressions,
            'parent'        => $tree->hasAttribute('parent')
                    ? $this->normalizeTemplateName($template, $tree->getAttribute('parent'))
                    : null,
            'includes'      => $includes,
            'name'          => $template,
        );

        return $atts;
    }

    protected function getParentInfo($template, $info)
    {
        if(!isset($info['parent'])) {
            return $info;
        }

        $parent = $this->getLocalInfo($info['parent']);
        $parent = $this->getIncludeInfo($info['parent'], $parent);

        if(isset($parent['parent'])) {
            $parent = $this->getParentInfo($parent['parent'], $parent);
        }

        $info['parentinfo'] = $parent;

        return $info;
    }

    protected function getIncludeInfo($template, $info, $covered = array())
    {
        if(!in_array($template, $covered)) {
            $covered[] = $template;

            if(isset($info['includes'])) {

                foreach($info['includes'] as &$include) {
                    foreach($include['templates'] as $inctemplate) {
                        $incinfo = $this->getLocalInfo($inctemplate);
                        $incinfo = $this->getParentInfo($inctemplate, $incinfo);
                        $include['info'][$inctemplate] = $this->getIncludeInfo($inctemplate, $incinfo, $covered);
                    }
                }
            }
        }

        return $info;
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

    protected function buildExpressions($variables, $elements)
    {
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
                $target['members'][$piece] = array();
                $target = &$target['members'][$piece];
            }
        }

        return $expressions;
    }

    protected function addLoopsToExpressions($loops, $expressions)
    {
        foreach($loops as $loop) {
            $loopitem = array('name' => $loop['iterator']);
            if(isset($expressions[$loop['value']])) {
                $loopitem['items'][$loop['value']] = $expressions[$loop['value']];
                unset($expressions[$loop['value']]);
            } else {
                $loopitem['items'][$loop['value']] = array();
            }
            if(isset($expressions[$loop['key']])) {
                $loopitem['keys'][$loop['key']] = $expressions[$loop['key']];
                unset($expressions[$loop['key']]);
            } else {
                $loopitem['keys'][$loop['key']] = array();
            }

            $this->insertIntoExpressions($expressions, $loopitem);
        }

        return $expressions;
    }

    protected function addForwards($includes, $expressions)
    {
        foreach($includes as $include) {
            if(isset($include['forwards'])) {
                foreach($include['forwards'] as $forward) {
                    $item = array(
                        'name' => $forward['source'],
                        'forwarded' => array(
                            'target' => $forward['target'],
                            'in' => $include['templates']
                        )
                    );

                    $this->insertIntoExpressions($expressions, $item);
                }
            }
        }

        return $expressions;
    }

    protected function insertIntoExpressions(&$expressions, $item)
    {
        if(strpos($item['name'], '.') !== false) {
            $pieces = explode('.', $item['name']);
            $name = array_shift($pieces);
            $remainder = join('.', $pieces);
        } else {
            $name = $item['name'];
            $remainder = '';
        }

        foreach($expressions as $itemname => &$structure) {
            if($name === $itemname) {
                if($remainder === '') {
                    if(isset($item['items']) && isset($item['keys'])) {
                        $structure['items'] = array_merge_recursive(
                            (isset($structure['items']) ? $structure['items'] : array()),
                            $item['items']
                        );
                        $structure['keys'] = array_merge_recursive(
                            (isset($structure['keys']) ? $structure['keys'] : array()),
                            $item['keys']
                        );
                    } elseif(isset($item['forwarded'])) {
                        $structure['forwarded'] = array_merge_recursive(
                            (isset($structure['forwarded']) ? $structure['forwarded'] : array()),
                            $item['forwarded']
                        );
                    }

                    return true;
                } else {
                    $item['name'] = $remainder;
                }
            }

            $val = false;

            if(isset($structure['members'])) {
                $val = $this->insertIntoExpressions($structure['members'], $item);
            }
            if(!$val && isset($structure['items'])) {
                $val = $this->insertIntoExpressions($structure['items'], $item);
            }
            if(!$val && isset($structure['keys'])) {
                $val = $this->insertIntoExpressions($structure['keys'], $item);
            }

            if($val) {
                return true;
            }
        }

        return false;
    }
}