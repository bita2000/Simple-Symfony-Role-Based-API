<?php
namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

class UserController extends AbstractController
{
    private $entityManager;
    private $passwordHasher;

    public function __construct(
        EntityManagerInterface $entityManager,
        UserPasswordHasherInterface $passwordHasher,
    ) {
        $this->entityManager = $entityManager;
        $this->passwordHasher = $passwordHasher;
    }

    public function getUsers(Request $request): JsonResponse
    {
        $userRepo = $this->entityManager->getRepository(User::class);

        if ($this->isGranted('ROLE_SUPER_ADMIN')) {
            // Super admin can see all users
            $users = $userRepo->findAll();
        } else {
            // Company admin and users can see users from their own company
            $currentUser = $this->getUser();
            $users = $userRepo->findBy(['company' => $currentUser->getCompany()]);
        }

        return $this->json($users, 200, [], ['groups' => ['user:read']]);
    }

    public function getUserById(Request $request, $id): JsonResponse
    {
        $userRepo = $this->entityManager->getRepository(User::class);
        $user = $userRepo->find($id);

        if (!$user) {
            return new JsonResponse(['error' => 'User not found'], 404);
        }

        if ($this->isGranted('ROLE_SUPER_ADMIN')) {
            // Super admin can see all users
        } else {
            $currentUser = $this->getUser();
            if ($user->getCompany() !== $currentUser->getCompany()) {
                return new JsonResponse(['error' => 'Access denied'], 403);
            }
        }

        return $this->json($user, 200, [], ['groups' => ['user:read']]);
    }

    public function createUser(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        // Validate required fields
        if (!isset($data['email'], $data['password'], $data['name'])) {
            return new JsonResponse(['error' => 'Missing required fields'], Response::HTTP_BAD_REQUEST);
        }

        $user = new User();
        $user->setEmail($data['email']);
        $user->setName($data['name']);

        $hashedPassword = $this->passwordHasher->hashPassword($user, $data['password']);
        $user->setPassword($hashedPassword);

        $roles = $data['roles'] ?? ['ROLE_USER'];

        // Only ROLE_SUPER_ADMIN can assign roles other than ROLE_USER
        if (!$this->isGranted('ROLE_SUPER_ADMIN') && $roles !== ['ROLE_USER']) {
            return new JsonResponse(['error' => 'You cannot assign roles other than ROLE_USER'], Response::HTTP_FORBIDDEN);
        }

        $user->setRoles($roles);

        if ($this->isGranted('ROLE_SUPER_ADMIN')) {
            // Super admin can assign any company
            if (isset($data['company_id'])) {
                $company = $this->entityManager->getRepository(Company::class)->find($data['company_id']);
                if (!$company) {
                    return new JsonResponse(['error' => 'Company not found'], Response::HTTP_BAD_REQUEST);
                }
                $user->setCompany($company);
            } else {
                return new JsonResponse(['error' => 'Company ID is required'], Response::HTTP_BAD_REQUEST);
            }
        } elseif ($this->isGranted('ROLE_COMPANY_ADMIN')) {
            // Company admin assigns their own company
            $currentUser = $this->getUser();
            $user->setCompany($currentUser->getCompany());
        } else {
            return new JsonResponse(['error' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
        }

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $this->json($user, Response::HTTP_CREATED, [], ['groups' => ['user:read']]);
    }

    public function deleteUser($id): JsonResponse
    {
        // Ensure only ROLE_SUPER_ADMIN can delete users
        if (!$this->isGranted('ROLE_SUPER_ADMIN')) {
            return new JsonResponse(['error' => 'Access denied'], 403);
        }

        $userRepo = $this->entityManager->getRepository(User::class);
        $user = $userRepo->find($id);

        if (!$user) {
            return new JsonResponse(['error' => 'User not found'], 404);
        }

        $this->entityManager->remove($user);
        $this->entityManager->flush();

        return new JsonResponse(null, 204);
    }
}
