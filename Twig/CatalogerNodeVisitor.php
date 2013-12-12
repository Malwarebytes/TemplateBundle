<?php

namespace Malwarebytes\TemplateBundle\Twig;

use Malwarebytes\TemplateBundle\Twig\MetadataNode;
use Twig_NodeVisitorInterface;
use Twig_NodeInterface;
use Twig_Environment;
use Twig_Node_Module;
use Twig_Node_Expression_Name;
use Twig_Node_Expression_GetAttr;
use Twig_Node_Expression_Constant;
use Twig_Node_Expression_AssignName;
use Twig_Node_For;
use Twig_Node_Include;
use Twig_Node_Expression_Array;

class CatalogerNodeVisitor implements Twig_NodeVisitorInterface
{
    protected $variables = array();
    protected $elements = array();
    protected $loops = array();
    protected $includes = array();
    protected $defaults = array();
    protected $parent;
    protected $inModule = false;
    protected $memberStack = array();
    protected $loopStack = array();

    public function enterNode(Twig_NodeInterface $node, Twig_Environment $env)
    {
        switch(true) {
            case ($node instanceof Twig_Node_Module && !$this->inModule):
                $parent = $node->getNode('parent');
                if($parent && $parent instanceof Twig_Node_Expression_Constant) {
                    $this->parent = $parent->getAttribute('value');
                }
                $this->variables = array();
                $this->inModule = true;
                break;
            case ($node instanceof Twig_Node_Expression_GetAttr):
                if(count($this->memberStack) == 0 || end($this->memberStack) == '<<TOP>>') {
                    array_push($this->memberStack, '<<TOP>>');
                }
                break;
            case ($node instanceof Twig_Node_Expression_Name && !($node instanceof Twig_Node_Expression_AssignName)):
                $isassigned = false;
                $name = $node->getAttribute('name');
                foreach($this->loopStack as $loop) {
                    if($loop['key'] == $name || $loop['value'] == $name) {
                        $isassigned = true;
                    }
                }
                if(!$isassigned && !in_array($name, $this->variables)) {
                    $this->variables[] = $name;
                }

                if(end($this->memberStack) == '<<TOP>>') {
                    array_push($this->memberStack, $name);
                }
                break;
            case ($node instanceof Twig_Node_Expression_Constant && count($this->memberStack) > 0):
                array_push($this->memberStack, $node->getAttribute('value'));
                break;
            case ($node instanceof Twig_Node_For):
                $loop = array();
                $loop['key'] = $node->getNode('key_target')->getAttribute('name');
                $loop['value'] = $node->getNode('value_target')->getAttribute('name');
                if($node->getNode('seq') instanceof Twig_Node_Expression_Name) {
                    $loop['iterator'] = $node->getNode('seq')->getAttribute('name');
                } else {
                    $loop['iterator'] = '<<GETATTR>>';
                }
                array_push($this->loopStack, $loop);
                break;
            case ($node instanceof MetadataNode):
                $ann = $node->getAttribute('annotation');
                $default = array('contents' => $ann->getContents(), 'type' => $ann->getType(), 'required' => $ann->getRequired());
                if(count($default) > 0) {
                    $this->defaults[$ann->getName()] = $default;
                }
                break;
        }

        return $node;
    }

    public function leaveNode(Twig_NodeInterface $node, Twig_Environment $env)
    {
        switch(true) {
            case ($node instanceof Twig_Node_Module && $this->inModule):
                $node->setAttribute('symbols', $this->variables);
                $node->setAttribute('elements', $this->elements);
                $node->setAttribute('loops', $this->loops);
                $node->setAttribute('includes', $this->includes);
                $node->setAttribute('defaults', $this->defaults);
                if(isset($this->parent)) {
                    $node->setAttribute('parent', $this->parent);
                }
                $this->inModule = false;
                $this->variables = array();
                $this->elements = array();
                $this->loops = array();
                $this->includes = array();
                $this->defaults = array();
                unset($this->parent);
                break;
            case ($node instanceof Twig_Node_Expression_GetAttr && count($this->memberStack) > 0):
                array_shift($this->memberStack);
                if(reset($this->memberStack) !== '<<TOP>>') {
                    $element = join('.', $this->memberStack);
                    if(!in_array($element, $this->elements)) {
                        $this->elements[] = $element;
                    }
                    $this->memberStack = array();

                    if(count($this->loopStack) > 0) {
                        $loop = end($this->loopStack);
                        if($loop['iterator'] == '<<GETATTR>>') {
                            $loop['iterator'] = $element;
                            array_pop($this->loopStack);
                            array_push($this->loopStack, $loop);
                        }
                    }
                    $node->setAttribute('attributeChain', $element);
                } else {
                    $stack = $this->memberStack;
                    while(reset($stack) == '<<TOP>>') {
                        array_shift($stack);
                    }
                    $node->setAttribute('attributeChain', join('.', $stack));
                }
                break;
            case ($node instanceof Twig_Node_For):
                $node->setAttribute('loopAttributes', end($this->loopStack));
                array_push($this->loops, array_pop($this->loopStack));
                break;
            case ($node instanceof Twig_Node_Include):
                $include = array();

                $expr = $node->getNode('expr');
                if($expr && $expr instanceof Twig_Node_Expression_Constant) {
                    $include['templates'] = array($expr->getAttribute('value'));
                } elseif($expr instanceof Twig_Node_Expression_Array) {
                    $pairs = $expr->getKeyValuePairs();
                    foreach($pairs as $pair) {
                        if($pair['value'] instanceof Twig_Node_Expression_Constant) {
                            $include['templates'][] = $pair['value']->getAttribute('value');
                        }
                    }
                }

                $vars = $node->getNode('variables');
                if($vars && $vars instanceof Twig_Node_Expression_Array) {
                    $pairs = $vars->getKeyValuePairs();
                    foreach($pairs as $pair) {
                        if(!$pair['value'] instanceof Twig_Node_Expression_Constant) {
                            $include['forwards'][] = array(
                                'source' => $this->getIdentifierOfNode($pair['value']),
                                'target' => $this->getIdentifierOfNode($pair['key'])
                            );
                        }
                    }
                }

                if(isset($include['forwards'])) {
                    $node->setAttribute('forwards', $include['forwards']);
                }

                $this->includes[] = $include;
                break;
        }

        return $node;
    }

    protected function getIdentifierOfNode($node)
    {
        switch(true) {
            case($node instanceof Twig_Node_Expression_Name):
                return $node->getAttribute('name');
            case($node instanceof Twig_Node_Expression_Constant):
                return '<<' . $node->getAttribute('value') . '>>';
            case($node instanceof Twig_Node_Expression_GetAttr):
                return $node->getAttribute('attributeChain');
            default:
                return '';
        }
    }


    public function getPriority()
    {
        return -10;
    }
}