<?php

namespace Malwarebytes\TemplateBundle\Form;

use Malwarebytes\TemplateBundle\Service\TemplateCatalog;
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
        $builder->addEventListener(FormEvents::PRE_SET_DATA, function(FormEvent $event) {
            $data = $event->getData();
            $form = $event->getForm();

            $form->add('template', 'text', array('label' => 'Template Name', 'data' => $data['template']));

            $info = $this->catalog->getInfo($data['template']);
        });
    }

    public function getName()
    {
        return 'template';
    }
}