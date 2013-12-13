<?php

namespace Malwarebytes\TemplateBundle\Form;

use Malwarebytes\TemplateBundle\Catalog\TemplateCatalog;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilder;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\Form\FormEvents;
use Symfony\Component\Form\FormEvent;

class TemplateDataFormType extends AbstractType
{
    protected $catalog;

    public function __construct(TemplateCatalog $catalog)
    {
        $this->catalog = $catalog;
    }

    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $build = function($tree, $prefix = '') use (&$build) {
            $fields = array();

            while(isset($tree['parentinfo'])) {
                $pi = $tree['parentinfo'];
                unset($tree['parentinfo']);
                $tree = array_merge_recursive($tree, $pi);
            }

            while(isset($tree['includes'])) {
                $includedata = array();
                foreach($tree['includes'] as $include) {
                    foreach($include['info'] as $info) {
                        $includedata = array_merge_recursive($includedata, $info);
                    }
                }
                unset($tree['includes']);
                $tree = array_merge_recursive($tree, $includedata);
            }

            foreach(array('expressions', 'members', 'items') as $sub) {

                if(isset($tree[$sub])) {
                    foreach($tree[$sub] as $name => $value) {
                        if((count($value) == 0) || isset($value['forwarded'])) {
                            $n = $prefix . $name;
                            if($sub === 'items') {
                                $n .= '---';
                            }
                            $fields[] = $n;
                        } else {
                            $delim = ($sub == 'items') ? '---:' : ':';
                            if($prefix !== '') {
                                $p = "{$prefix}{$name}{$delim}";
                            } else {
                                $p = "{$name}{$delim}";
                            }
                            $fields = array_merge($fields, $build($value, $p));
                        }
                    }
                }
            }

            if($prefix === '') {
                $fullfields = array();
                foreach($fields as $field) {
                    if(isset($tree['defaults'][$field])) {
                        $fullfields[$field] = $tree['defaults'][$field];
                    } else {
                        $fullfields[$field] = array();
                    }
                }

                return $fullfields;
            } else {
                return $fields;
            }
        };

        $builder->addEventListener(FormEvents::PRE_SET_DATA, function(FormEvent $event) use ($build) {
            $data = $event->getData();
            $form = $event->getForm();

            $form->add('__template', 'hidden', array('label' => 'Template Name', 'data' => $data['__template']));

            $info = $this->catalog->getInfo($data['__template']);

            $fields = $build($info);

            if(isset($info['defaults'])) {
                foreach($info['defaults'] as $name => $default) {
                    $settings = array('data' => $default['contents']);
                    if($default['type'] !== 'text') {
                        $type = 'hidden';
                        $fieldname = $default['type'] . '-:-' . $name;

                        $form->add($fieldname, $type, $settings);

                        foreach($fields as $field => $default) {
                            if(strpos($field, $name) === 0) {
                                unset($fields[$field]);
                            }
                        }
                    }
                }
            }

            foreach($fields as $field => $default) {
                $settings = array('label' => $field);
                if(isset($default['required'])) {
                    $settings['required'] = $default['required'];
                }
                $type = 'text';
                if(isset($default['contents'])) {
                    if(!isset($default['type']) || $default['type'] === 'text') {
                        $settings['data'] = $default['contents'];
                    }
                }

                $form->add($field, $type, $settings);
            }

            $form->add('render', 'submit', array('label' => 'Render Template'));

        });
    }

    public function getName()
    {
        return 'template';
    }
}