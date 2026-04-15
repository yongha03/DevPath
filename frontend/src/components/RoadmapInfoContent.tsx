type RoadmapInfoContentProps = {
  content: string | null | undefined
}

function sanitizeHtml(content: string) {
  return content
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/\son\w+="[^"]*"/gi, '')
    .replace(/\son\w+='[^']*'/gi, '')
}

export default function RoadmapInfoContent({ content }: RoadmapInfoContentProps) {
  const normalized = content?.trim()

  if (!normalized) {
    return null
  }

  if (!normalized.includes('<')) {
    return <div className="roadmap-info-html"><p>{normalized}</p></div>
  }

  return (
    <div
      className="roadmap-info-html"
      dangerouslySetInnerHTML={{ __html: sanitizeHtml(normalized) }}
    />
  )
}
