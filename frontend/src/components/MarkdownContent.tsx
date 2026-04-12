import type { ElementType, ReactNode } from 'react'

type MarkdownContentProps = {
  content: string | null | undefined
  className?: string
}

function sanitizeUrl(url: string) {
  const normalized = url.trim()

  if (!normalized) {
    return null
  }

  if (/^(https?:\/\/|\/|#)/i.test(normalized)) {
    return normalized
  }

  return null
}

function renderInlineMarkdown(text: string, keyPrefix: string): ReactNode[] {
  const pattern =
    /!\[([^\]]*)\]\(([^)]+)\)|\[([^\]]+)\]\(([^)]+)\)|\*\*([^*]+)\*\*|\*([^*]+)\*|`([^`]+)`/g
  const nodes: ReactNode[] = []
  let lastIndex = 0
  let match: RegExpExecArray | null
  let nodeIndex = 0

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index))
    }

    if (match[1] !== undefined && match[2] !== undefined) {
      const imageUrl = sanitizeUrl(match[2])
      if (imageUrl) {
        nodes.push(
          <img
            key={`${keyPrefix}-image-${nodeIndex}`}
            src={imageUrl}
            alt={match[1] || 'markdown image'}
            className="my-4 max-h-80 w-full rounded-2xl border border-gray-200 bg-white object-cover"
          />,
        )
      } else {
        nodes.push(match[0])
      }
    } else if (match[3] !== undefined && match[4] !== undefined) {
      const href = sanitizeUrl(match[4])
      if (href) {
        nodes.push(
          <a
            key={`${keyPrefix}-link-${nodeIndex}`}
            href={href}
            target={href.startsWith('#') ? undefined : '_blank'}
            rel={href.startsWith('#') ? undefined : 'noreferrer'}
            className="font-semibold text-[#00c471] underline underline-offset-4"
          >
            {match[3]}
          </a>,
        )
      } else {
        nodes.push(match[0])
      }
    } else if (match[5] !== undefined) {
      nodes.push(
        <strong key={`${keyPrefix}-strong-${nodeIndex}`} className="font-extrabold text-gray-900">
          {match[5]}
        </strong>,
      )
    } else if (match[6] !== undefined) {
      nodes.push(
        <em key={`${keyPrefix}-em-${nodeIndex}`} className="italic">
          {match[6]}
        </em>,
      )
    } else if (match[7] !== undefined) {
      nodes.push(
        <code
          key={`${keyPrefix}-code-${nodeIndex}`}
          className="rounded-md bg-gray-900/95 px-1.5 py-0.5 font-mono text-[0.92em] text-white"
        >
          {match[7]}
        </code>,
      )
    }

    lastIndex = match.index + match[0].length
    nodeIndex += 1
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex))
  }

  return nodes
}

function renderParagraphLines(lines: string[], keyPrefix: string) {
  const nodes: ReactNode[] = []

  lines.forEach((line, lineIndex) => {
    if (lineIndex > 0) {
      nodes.push(<br key={`${keyPrefix}-break-${lineIndex}`} />)
    }
    nodes.push(...renderInlineMarkdown(line, `${keyPrefix}-line-${lineIndex}`))
  })

  return nodes
}

function renderBlocks(content: string) {
  const lines = content.replace(/\r\n/g, '\n').split('\n')
  const blocks: ReactNode[] = []
  let index = 0

  while (index < lines.length) {
    const line = lines[index]

    if (!line.trim()) {
      index += 1
      continue
    }

    if (line.startsWith('```')) {
      const codeLines: string[] = []
      index += 1

      while (index < lines.length && !lines[index].startsWith('```')) {
        codeLines.push(lines[index])
        index += 1
      }

      if (index < lines.length) {
        index += 1
      }

      blocks.push(
        <pre
          key={`code-block-${blocks.length}`}
          className="overflow-x-auto rounded-[22px] bg-gray-950 px-5 py-4 text-sm leading-7 text-gray-100"
        >
          <code>{codeLines.join('\n')}</code>
        </pre>,
      )
      continue
    }

    const headingMatch = line.match(/^(#{1,6})\s+(.+)$/)
    if (headingMatch) {
      const level = headingMatch[1].length
      const HeadingTag = `h${level}` as ElementType
      const headingClassName =
        level <= 2
          ? 'text-xl font-black text-gray-900'
          : level === 3
            ? 'text-lg font-extrabold text-gray-900'
            : 'text-base font-bold text-gray-900'

      blocks.push(
        <HeadingTag key={`heading-${blocks.length}`} className={headingClassName}>
          {renderInlineMarkdown(headingMatch[2], `heading-${blocks.length}`)}
        </HeadingTag>,
      )
      index += 1
      continue
    }

    if (/^>\s?/.test(line)) {
      const quoteLines: string[] = []

      while (index < lines.length && /^>\s?/.test(lines[index])) {
        quoteLines.push(lines[index].replace(/^>\s?/, ''))
        index += 1
      }

      blocks.push(
        <blockquote
          key={`blockquote-${blocks.length}`}
          className="rounded-r-2xl border-l-4 border-[#00c471] bg-green-50/70 px-5 py-4 text-sm leading-7 text-gray-700"
        >
          {renderParagraphLines(quoteLines, `blockquote-${blocks.length}`)}
        </blockquote>,
      )
      continue
    }

    if (/^[-*]\s+/.test(line)) {
      const items: string[] = []

      while (index < lines.length && /^[-*]\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^[-*]\s+/, ''))
        index += 1
      }

      blocks.push(
        <ul key={`ul-${blocks.length}`} className="space-y-2 pl-5 text-sm leading-7 text-gray-700">
          {items.map((item, itemIndex) => (
            <li key={`ul-${blocks.length}-item-${itemIndex}`} className="list-disc">
              {renderInlineMarkdown(item, `ul-${blocks.length}-${itemIndex}`)}
            </li>
          ))}
        </ul>,
      )
      continue
    }

    if (/^\d+\.\s+/.test(line)) {
      const items: string[] = []

      while (index < lines.length && /^\d+\.\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\d+\.\s+/, ''))
        index += 1
      }

      blocks.push(
        <ol key={`ol-${blocks.length}`} className="space-y-2 pl-5 text-sm leading-7 text-gray-700">
          {items.map((item, itemIndex) => (
            <li key={`ol-${blocks.length}-item-${itemIndex}`} className="list-decimal">
              {renderInlineMarkdown(item, `ol-${blocks.length}-${itemIndex}`)}
            </li>
          ))}
        </ol>,
      )
      continue
    }

    const paragraphLines = [line]
    index += 1

    while (
      index < lines.length &&
      lines[index].trim() &&
      !lines[index].startsWith('```') &&
      !/^(#{1,6})\s+/.test(lines[index]) &&
      !/^>\s?/.test(lines[index]) &&
      !/^[-*]\s+/.test(lines[index]) &&
      !/^\d+\.\s+/.test(lines[index])
    ) {
      paragraphLines.push(lines[index])
      index += 1
    }

    blocks.push(
      <p key={`paragraph-${blocks.length}`} className="text-sm leading-7 font-medium text-gray-700">
        {renderParagraphLines(paragraphLines, `paragraph-${blocks.length}`)}
      </p>,
    )
  }

  return blocks
}

export default function MarkdownContent({ content, className = '' }: MarkdownContentProps) {
  const normalized = content?.trim()

  if (!normalized) {
    return null
  }

  return <div className={`space-y-4 ${className}`.trim()}>{renderBlocks(normalized)}</div>
}
