type UserAvatarProps = {
  name: string
  imageUrl?: string | null
  className?: string
  iconClassName?: string
  alt?: string
}

function resolveImageUrl(imageUrl?: string | null) {
  const normalized = imageUrl?.trim()
  return normalized ? normalized : null
}

export default function UserAvatar({
  name,
  imageUrl,
  className = 'h-9 w-9',
  iconClassName = 'text-sm',
  alt,
}: UserAvatarProps) {
  const resolvedImageUrl = resolveImageUrl(imageUrl)
  const baseClassName = `shrink-0 overflow-hidden rounded-full border border-gray-200 ${className}`

  if (resolvedImageUrl) {
    return <img src={resolvedImageUrl} alt={alt ?? `${name} profile`} className={`${baseClassName} object-cover`} />
  }

  return (
    <span
      role="img"
      aria-label={alt ?? `${name} default profile`}
      className={`${baseClassName} inline-flex items-center justify-center bg-gray-100 text-gray-400`}
    >
      <i className={`fas fa-user ${iconClassName}`} />
    </span>
  )
}
