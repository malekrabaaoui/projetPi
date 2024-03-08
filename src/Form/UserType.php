<?php

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints as Assert;

class UserType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('username', null, [
                'label' => 'Username',
            ])
            ->add('email', null, [
                'label' => 'Email',
                'constraints' => [
                    new Assert\NotBlank(),
                    new Assert\Regex([
                        'pattern' => '/@/',
                        'message' => 'The email address must contain the "@" symbol.',
                    ]),
                ],
            ])
            // Change 'password' field to 'plainPassword' and use PasswordType
            ->add('plainPassword', PasswordType::class, [
                'label' => 'Password',
                'constraints' => [
                    new Assert\NotBlank(),
                    new Assert\Regex([
                        'pattern' => '/^(?=.*[A-Z])(?=.*[0-9])/',
                        'message' => 'The password must contain at least one uppercase letter and one digit.',
                    ]),
                ],
            ])
            ->add('idanimal', null, [
                'label' => 'ID Animal',
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => User::class,
            'csrf_protection' => false, // Assuming you're not using CSRF protection for API endpoints
        ]);
    }
}
