<?php
namespace App\Controller;

use App\Entity\Company;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;

class CompanyController extends AbstractController
{
    private $entityManager;

    public function __construct(EntityManagerInterface $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    public function getCompanies(): JsonResponse
    {
        $companyRepo = $this->entityManager->getRepository(Company::class);
        $companies = $companyRepo->findAll();

        return $this->json($companies, 200, [], ['groups' => ['company:read']]);
    }

    public function getCompany($id): JsonResponse
    {
        $companyRepo = $this->entityManager->getRepository(Company::class);
        $company = $companyRepo->find($id);

        if (!$company) {
            return new JsonResponse(['error' => 'Company not found'], 404);
        }

        return $this->json($company, 200, [], ['groups' => ['company:read']]);
    }

    public function createCompany(Request $request): JsonResponse
    {
        // Only ROLE_SUPER_ADMIN can create companies
        if (!$this->isGranted('ROLE_SUPER_ADMIN')) {
            return new JsonResponse(['error' => 'Access denied'], 403);
        }

        $data = json_decode($request->getContent(), true);

        if (!isset($data['name'])) {
            return new JsonResponse(['error' => 'Name is required'], 400);
        }

        $company = new Company();
        $company->setName($data['name']);

        $this->entityManager->persist($company);
        $this->entityManager->flush();

        return $this->json($company, 201, [], ['groups' => ['company:read']]);
    }

    public function deleteCompany($id): JsonResponse
    {
        if (!$this->isGranted('ROLE_SUPER_ADMIN')) {
            return new JsonResponse(['error' => 'Access denied'], 403);
        }

        $companyRepo = $this->entityManager->getRepository(Company::class);
        $company = $companyRepo->find($id);

        if (!$company) {
            return new JsonResponse(['error' => 'Company not found'], 404);
        }

        $this->entityManager->remove($company);
        $this->entityManager->flush();

        return new JsonResponse(null, 204);
    }
}
