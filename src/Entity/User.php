<?php
namespace App\Entity;

use ApiPlatform\Metadata\ApiResource;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Serializer\Annotation\Groups;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Post;
use ApiPlatform\Metadata\Delete;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;

#[ApiResource(
    normalizationContext: ['groups' => ['user:read']],
    denormalizationContext: ['groups' => ['user:write']],
    operations: [
        new GetCollection(
            controller: 'App\Controller\UserController::getUsers',
            security: "is_granted('ROLE_USER')",
            securityMessage: "Access denied."
        ),
        new Get(
            controller: 'App\Controller\UserController::getUserById',
            security: "is_granted('ROLE_USER')",
            securityMessage: "Access denied."
        ),
        new Post(
            controller: 'App\Controller\UserController::createUser',
            security: "is_granted('ROLE_COMPANY_ADMIN') or is_granted('ROLE_SUPER_ADMIN')",
            securityMessage: "Only admins can create users."
        ),
        new Delete(
            controller: 'App\Controller\UserController::deleteUser',
            security: "is_granted('ROLE_SUPER_ADMIN')",
            securityMessage: "Only super admins can delete users."
        ),
    ]
)]

#[ORM\Entity]
#[ApiResource]
#[ORM\Table(name: '`user`')]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    public const ROLE_USER = 'ROLE_USER';
    public const ROLE_COMPANY_ADMIN = 'ROLE_COMPANY_ADMIN';
    public const ROLE_SUPER_ADMIN = 'ROLE_SUPER_ADMIN';

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    #[Groups(['user:read'])]
    private ?int $id = null;

    #[ORM\Column(type: 'string', length: 180, unique: true)]
    #[Assert\NotBlank]
    #[Assert\Email]
    #[Groups(['user:read', 'user:write'])]
    private string $email;

    #[ORM\Column(type: 'json')]
    private array $roles = [];

    #[ORM\Column(type: 'string')]
    #[Groups(['user:write'])]
    private string $password;

    #[ORM\Column(type: 'string', length: 100)]
    #[Assert\NotBlank]
    #[Assert\Length(min: 3, max: 100)]
    #[Assert\Regex(
        pattern: "/^[A-Za-z\s\-'’]+$/u",
        message: "Name can only contain letters, spaces, hyphens, and apostrophes."
    )]
    #[Assert\Regex(
        pattern: "/[A-Z]/",
        message: "Name must contain at least one uppercase letter."
    )]
    private string $name;

    #[ORM\ManyToOne(targetEntity: Company::class)]
    #[Groups(['user:read', 'user:write'])]
    private ?Company $company = null;

    public function setName(string $name): self
    {
        $this->name = $name;

        return $this;
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUserIdentifier(): string
    {
        return $this->email;
    }

    #[Groups(['user:read', 'user:write'])]
    public function getRoles(): array
    {
        $roles = $this->roles;
        if (empty($roles)) {
            $roles[] = 'ROLE_USER';
        }
        return array_unique($roles);
    }

    public function setRoles(array $roles): self
    {
        $this->roles = $roles;
        return $this;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): self
    {
        $this->email = $email;
        return $this;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): self
    {
        $this->password = $password;
        return $this;
    }

    #[Groups(['user:read'])]
    public function getCompanyId(): ?int
    {
        return $this->company ? $this->company->getId() : null;
    }

    public function setCompany(?Company $company): self
    {
        $this->company = $company;

        return $this;
    }

    public function eraseCredentials(): void
    {
    }
}
