<?php

namespace Malwarebytes\TemplateBundle\Twig;

use Twig_NodeVisitorInterface,
    Twig_NodeInterface,
    Twig_Environment,
    Twig_Node_Module,
    Twig_Node_Expression_Name,
    Twig_Node_Expression_GetAttr,
    Twig_Node_Expression_Constant,
    Twig_Node_Expression_AssignName,
    Twig_Node_For,
    Twig_Node_Include,
    Twig_Node_Expression_Array;

class CatalogerNodeVisitor implements Twig_NodeVisitorInterface
{
    protected $variables = array();
    protected $elements = array();
    protected $loops = array();
    protected $includes = array();
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
                        if($pair['value'] instanceof Twig_Node_Expression_Name
                           && $pair['key'] instanceof Twig_Node_Expression_Constant) {
                            $include['forwards'][] = array(
                                'source' => $pair['value']->getAttribute('name'),
                                'target' => $pair['key']->getAttribute('value')
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

    public function leaveNode(Twig_NodeInterface $node, Twig_Environment $env)
    {
        switch(true) {
            case ($node instanceof Twig_Node_Module && $this->inModule):
                $node->setAttribute('symbols', $this->variables);
                $node->setAttribute('elements', $this->elements);
                $node->setAttribute('loops', $this->loops);
                $node->setAttribute('includes', $this->includes);
                if(isset($this->parent)) {
                    $node->setAttribute('parent', $this->parent);
                }
                $this->inModule = false;
                $this->variables = array();
                $this->elements = array();
                $this->loops = array();
                $this->includes = array();
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
        }

        return $node;
    }

    public function getPriority()
    {
        return -10;
    }
}