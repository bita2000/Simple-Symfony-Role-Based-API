<?php

namespace App\Entity;

use ApiPlatform\Metadata\ApiResource;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Validator\Constraints as Assert;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Post;
use ApiPlatform\Metadata\Delete;

#[ApiResource(
    operations: [
        new GetCollection(
            controller: 'App\Controller\CompanyController::getCompanies',
            security: "is_granted('ROLE_USER')",
            securityMessage: "Access denied."
        ),
        new Get(
            controller: 'App\Controller\CompanyController::getCompany',
            security: "is_granted('ROLE_USER')",
            securityMessage: "Access denied."
        ),
        new Post(
            controller: 'App\Controller\CompanyController::createCompany',
            security: "is_granted('ROLE_SUPER_ADMIN')",
            securityMessage: "Only super admins can create companies."
        ),
        new Delete(
            controller: 'App\Controller\CompanyController::deleteCompany',
            security: "is_granted('ROLE_SUPER_ADMIN')",
            securityMessage: "Only super admins can delete companies."
        ),
    ]
)]

#[ORM\Entity]
#[ApiResource]
class Company
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 100, unique: true)]
    #[Assert\NotBlank]
    #[Assert\Length(min: 5, max: 100)]
    private string $name;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): self
    {
        $this->name = $name;
        return $this;
    }
}