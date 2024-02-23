<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use App\Form\SecondUserType;
use App\Form\LoginUserType;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;









#[Route('/user')]
class UserController extends AbstractController
{
    private $passwordEncoder;

    public function __construct(UserPasswordEncoderInterface $passwordEncoder)
    {
        $this->passwordEncoder = $passwordEncoder;
    }

    #[Route('/login', name: 'app_login')]
    public function login(Request $request): Response
    {
        // Create the login form using the UserType form type class
        $form = $this->createForm(LoginUserType::class);

        // Render the login form template and pass the form object to it
        return $this->render('user/signin.html.twig', [
            'form' => $form->createView(), // Pass the form view to the template
        ]);
    }


    #[Route('/check-login', name: 'check_login', methods: ['POST'])]
    public function checkLogin(Request $request, UserPasswordEncoderInterface $passwordEncoder): Response
    {
        // Extract username and password from the request
        $username = $request->request->get('username');
        $password = $request->request->get('password');
    
        // Query the database to find the user by username
        $userRepository = $this->getDoctrine()->getRepository(User::class);
        $user = $userRepository->findOneBy(['username' => $username]);
    
        if ($user !== null) {
            // Check if the provided password matches the hashed password in the database
            if ($passwordEncoder->isPasswordValid($user, $password)) {
                $role = $user->getRole();
                if (strtolower($role) === 'client') { // Case-insensitive comparison
                    return $this->redirectToRoute('app_user_index');
                } elseif (strtoupper($role) === 'ADMIN') { // Assuming ADMIN is in uppercase
                    return $this->redirectToRoute('app_fetch_employee');
                } else {
                    // Handle other roles or cases here
                    return $this->redirectToRoute('app_fetch_employee');
                }
            } else {
                // Incorrect password
                return $this->redirectToRoute('app_login', ['error' => 'Invalid credentials']);
            }
        } else {
            // User not found
            return $this->redirectToRoute('app_login', ['error' => 'User not found']);
        }
    }


    #[Route('/', name: 'app_user_index', methods: ['GET'])]
    public function index(UserRepository $userRepository): Response
    {
        // Call the custom method in UserRepository to fetch users with role "client"
        $users = $userRepository->findByRole('client');
    
        return $this->render('user/index.html.twig', [
            'users' => $users,
        ]);
    }




    #[Route('/showemployee', name: 'app_fetch_employee', methods: ['GET'])]
    public function fetchemployee(UserRepository $userRepository): Response
    {
        // Call the custom method in UserRepository to fetch users with role "client"
        $users = $userRepository->findByRole('employee');
    
        return $this->render('user/fetchemployee.html.twig', [
            'users' => $users,
        ]);
    }

    



    #[Route('/new', name: 'app_user_new', methods: ['GET', 'POST'])]
    public function new(Request $request, EntityManagerInterface $entityManager, UserPasswordEncoderInterface $passwordEncoder): Response
    {
        $user = new User();
        $user->setRole('client'); // Set default role here
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);
    
        if ($form->isSubmitted() && $form->isValid()) {
            // Hash the plain-text password before persisting the user
            $plainPassword = $user->getPlainPassword();
            $hashedPassword = $passwordEncoder->encodePassword($user, $plainPassword);
            $user->setPassword($hashedPassword);
    
            $entityManager->persist($user);
            $entityManager->flush();
    
            return $this->redirectToRoute('app_user_index', [], Response::HTTP_SEE_OTHER);
        }
    
        return $this->renderForm('user/new.html.twig', [
            'user' => $user,
            'form' => $form,
        ]);
    }
    
    #[Route('/new_employee', name: 'app_user_new_employee', methods: ['GET', 'POST'])]
    public function new_employee(Request $request, EntityManagerInterface $entityManager, UserPasswordEncoderInterface $passwordEncoder): Response
    {
        $user = new User();
        $user->setRole('employee'); // Set default role here
        $user->setIdanimal(0); // Set default role here
        $form = $this->createForm(SecondUserType::class, $user); // Change UserType to SecondUserType
        $form->handleRequest($request);
    
        if ($form->isSubmitted() && $form->isValid()) {
            // Hash the plain-text password before persisting the user
            $plainPassword = $user->getPlainPassword();
            $hashedPassword = $passwordEncoder->encodePassword($user, $plainPassword);
            $user->setPassword($hashedPassword);
    
            $entityManager->persist($user);
            $entityManager->flush();
    
            return $this->redirectToRoute('app_fetch_employee', [], Response::HTTP_SEE_OTHER);
        }
    
        return $this->renderForm('user/new_employee.html.twig', [
            'user' => $user,
            'form' => $form,
        ]);
    }
    




    #[Route('/{id}/edit', name: 'app_user_edit', methods: ['GET', 'POST'])]
    public function edit(Request $request, User $user, EntityManagerInterface $entityManager): Response
    {
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $entityManager->flush();

            return $this->redirectToRoute('app_user_index', [], Response::HTTP_SEE_OTHER);
        }

        return $this->renderForm('user/edit.html.twig', [
            'user' => $user,
            'form' => $form,
        ]);
    }





    #[Route('/{id}/edit_employee', name: 'app_user_edit_employee', methods: ['GET', 'POST'])]
    public function edit_employee(Request $request, User $user, EntityManagerInterface $entityManager): Response
    {
        $form = $this->createForm(SecondUserType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $entityManager->flush();

            return $this->redirectToRoute('app_fetch_employee', [], Response::HTTP_SEE_OTHER);
        }

        return $this->renderForm('user/edit_employee.html.twig', [
            'user' => $user,
            'form' => $form,
        ]);
    }





    #[Route('/{id}', name: 'app_user_delete', methods: ['POST'])]
    public function delete(Request $request, User $user, EntityManagerInterface $entityManager): Response
    {
        if ($this->isCsrfTokenValid('delete'.$user->getId(), $request->request->get('_token'))) {
            $entityManager->remove($user);
            $entityManager->flush();
        }

        return $this->redirectToRoute('app_user_index', [], Response::HTTP_SEE_OTHER);
    }




}
