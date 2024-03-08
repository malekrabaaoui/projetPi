<?php

namespace App\Form;

use App\Entity\User;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;



class SecondUserType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options)
    {
        $builder
            ->add('username', null, [
                'label' => 'Username',
                // Other options...
            ])
            ->add('email', null, [
                'label' => 'email',
                // Other options...
            ])
            ->add('plainPassword', PasswordType::class, [
                'label' => 'Password',
                'constraints' => [
                    new Assert\NotBlank(),
                    new Assert\Regex([
                        'pattern' => '/^(?=.*[A-Z])(?=.*[0-9])/',
                        'message' => 'The password must contain at least one uppercase letter and one digit.',
                    ]),
                ],
            ]);
        }
    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => User::class,
        ]);
    }
}
