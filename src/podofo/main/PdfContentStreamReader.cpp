/**
 * SPDX-FileCopyrightText: (C) 2022 Francesco Pretto <ceztko@gmail.com>
 * SPDX-License-Identifier: LGPL-2.0-or-later
 * SPDX-License-Identifier: MPL-2.0
 */

#include <podofo/private/PdfDeclarationsPrivate.h>
#include "PdfContentStreamReader.h"

#include "PdfXObjectForm.h"
#include "PdfOperatorUtils.h"
#include "PdfCanvasInputDevice.h"
#include "PdfData.h"
#include "PdfDictionary.h"

using namespace std;
using namespace PoDoFo;

PdfContentStreamReader::PdfContentStreamReader(const PdfCanvas& canvas,
        nullable<const PdfContentReaderArgs&> args) :
    PdfContentStreamReader(std::make_shared<PdfCanvasInputDevice>(canvas),
        &canvas, args) { }

PdfContentStreamReader::PdfContentStreamReader(const shared_ptr<InputStreamDevice>& device,
        nullable<const PdfContentReaderArgs&> args) :
    PdfContentStreamReader(device, nullptr, args) { }

PdfContentStreamReader::PdfContentStreamReader(const shared_ptr<InputStreamDevice>& device,
    const PdfCanvas* canvas, nullable<const PdfContentReaderArgs&> args) :
    m_args(args.has_value() ? *args : PdfContentReaderArgs()),
    m_buffer(std::make_shared<charbuff>(PdfTokenizer::BufferSize)),
    m_tokenizer(m_buffer),
    m_readingInlineImgData(false),
    m_temp{ }
{
    if (device == nullptr)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidHandle, "Device must be non null");

    m_inputs.push_back({ nullptr, device, canvas });
}

bool PdfContentStreamReader::TryReadNext(PdfContent& content)
{
    beforeReadReset(content);

    while (true)
    {
        if (m_inputs.size() == 0)
            goto Eof;

        if (m_readingInlineImgData)
        {
            if (m_args.InlineImageHandler == nullptr)
            {
                if (!tryReadInlineImgData(content.InlineImageData))
                    goto PopDevice;

                content.Type = PdfContentType::ImageData;
                m_readingInlineImgData = false;
                afterReadClear(content);
                return true;
            }
            else
            {
                bool eof = !m_args.InlineImageHandler(content.InlineImageDictionary, *m_inputs.back().Device);
                m_readingInlineImgData = false;

                // Try to consume the EI end image operator
                if (eof || !tryReadNextContent(content))
                {
                    content.Warnings = PdfContentWarnings::MissingEndImage;
                    goto PopDevice;
                }

                if (content.Operator != PdfOperator::EI)
                {
                    content.Warnings = PdfContentWarnings::MissingEndImage;
                    goto HandleContent;
                }

                beforeReadReset(content);
            }
        }

        if (!tryReadNextContent(content))
            goto PopDevice;

    HandleContent:
        afterReadClear(content);
        handleWarnings();
        return true;

    PopDevice:
        PODOFO_INVARIANT(m_inputs.size() != 0);
        m_inputs.pop_back();
        if (m_inputs.size() == 0)
            goto Eof;

        // Unless the device stack is empty, popping a devices
        // means that we finished processing an XObject form
        content.Type = PdfContentType::EndXObjectForm;
        if (content.Stack.GetSize() != 0)
            content.Warnings |= PdfContentWarnings::SpuriousStackContent;

        goto HandleContent;

    Eof:
        content.Type = PdfContentType::Unknown;
        afterReadClear(content);
        return false;
    }
}

// Returns false in case of EOF
bool PdfContentStreamReader::tryReadNextContent(PdfContent& content)
{
    while (true)
    {
        bool gotToken = m_tokenizer.TryReadNext(*m_inputs.back().Device, m_temp.PsType, content.Keyword, m_temp.Variant);
        if (!gotToken)
        {
            content.Type = PdfContentType::Unknown;
            return false;
        }

        switch (m_temp.PsType)
        {
            case PdfPostScriptTokenType::Keyword:
            {
                if (!TryGetPdfOperator(content.Keyword, content.Operator))
                {
                    content.Type = PdfContentType::UnexpectedKeyword;
                    return true;
                }

                content.Type = PdfContentType::Operator;
                int operandCount = PoDoFo::GetOperandCount(content.Operator);
                if (operandCount != -1 && content.Stack.GetSize() != (unsigned)operandCount)
                {
                    if (content.Stack.GetSize() < (unsigned)operandCount)
                        content.Warnings |= PdfContentWarnings::InvalidOperator;
                    else // Stack.GetSize() > operandCount
                        content.Warnings |= PdfContentWarnings::SpuriousStackContent;
                }

                if (!tryHandleOperator(content))
                    return false;

                return true;
            }
            case PdfPostScriptTokenType::Variant:
            {
                content.Stack.Push(std::move(m_temp.Variant));
                continue;
            }
            case PdfPostScriptTokenType::ProcedureEnter:
            case PdfPostScriptTokenType::ProcedureExit:
            {
                content.Type = PdfContentType::UnexpectedKeyword;
                return true;
            }
            default:
            {
                PODOFO_RAISE_ERROR(PdfErrorCode::InvalidEnumValue);
            }
        }
    }
}

void PdfContentStreamReader::beforeReadReset(PdfContent& content)
{
    content.Stack.Clear();
    content.Warnings = PdfContentWarnings::None;
}

void PdfContentStreamReader::afterReadClear(PdfContent& content)
{
    // Do some cleaning
    switch (content.Type)
    {
        case PdfContentType::Operator:
        {
            content.InlineImageDictionary.Clear();
            content.InlineImageData.clear();
            content.XObject = nullptr;
            content.Name = nullptr;
            break;
        }
        case PdfContentType::ImageDictionary:
        {
            content.Operator = PdfOperator::Unknown;
            content.Keyword = string_view();
            content.InlineImageData.clear();
            content.XObject = nullptr;
            content.Name = nullptr;
            break;
        }
        case PdfContentType::ImageData:
        {
            content.Operator = PdfOperator::Unknown;
            content.Keyword = string_view();
            content.InlineImageDictionary.Clear();
            content.XObject = nullptr;
            content.Name = nullptr;
            break;
        }
        case PdfContentType::DoXObject:
        {
            content.Operator = PdfOperator::Unknown;
            content.Keyword = string_view();
            content.InlineImageDictionary.Clear();
            content.InlineImageData.clear();
            break;
        }
        case PdfContentType::UnexpectedKeyword:
        {
            content.Operator = PdfOperator::Unknown;
            content.InlineImageDictionary.Clear();
            content.InlineImageData.clear();
            content.XObject = nullptr;
            content.Name = nullptr;
            break;
        }
        case PdfContentType::Unknown:
        case PdfContentType::EndXObjectForm:
        {
            // Used when it is reached the EOF
            content.Operator = PdfOperator::Unknown;
            content.Keyword = string_view();
            content.InlineImageDictionary.Clear();
            content.InlineImageData.clear();
            content.XObject = nullptr;
            content.Name = nullptr;
            break;
        }
        default:
        {
            PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InternalLogic, "Unsupported flow");
        }
    }
}

// Returns false in case of EOF
bool PdfContentStreamReader::tryHandleOperator(PdfContent& content)
{
    // By default it's not handled
    switch (content.Operator)
    {
        case PdfOperator::Do:
        {
            if (m_inputs.back().Canvas == nullptr)
            {
                // Don't follow XObject and return raw operator
                return true;
            }

            tryFollowXObject(content);
            return true;
        }
        case PdfOperator::BI:
        {
            if (!tryReadInlineImgDict(content))
                return false;

            content.Type = PdfContentType::ImageDictionary;
            m_readingInlineImgData = true;
            return true;
        }
        default:
        {
            // Not handled operator
            return true;
        }
    }
}

// Returns false in case of EOF
bool PdfContentStreamReader::tryReadInlineImgDict(PdfContent& content)
{
    while (true)
    {
        if (!m_tokenizer.TryReadNext(*m_inputs.back().Device, m_temp.PsType, m_temp.Keyword, m_temp.Variant))
            return false;

        switch (m_temp.PsType)
        {
            case PdfPostScriptTokenType::Keyword:
            {
                // Try to find end of dictionary
                if (m_temp.Keyword == "ID")
                    return true;

                content.Warnings |= PdfContentWarnings::InvalidImageDictionaryContent;
                continue;
            }
            case PdfPostScriptTokenType::Variant:
            {
                if (m_temp.Variant.TryGetName(m_temp.Name))
                    break;

                content.Warnings |= PdfContentWarnings::InvalidImageDictionaryContent;
                continue;
            }
            default:
            {
                content.Warnings |= PdfContentWarnings::InvalidImageDictionaryContent;
                continue;
            }
        }

        if (m_tokenizer.TryReadNextVariant(*m_inputs.back().Device, m_temp.Variant))
            content.InlineImageDictionary.AddKey(m_temp.Name, std::move(m_temp.Variant));
        else
            return false;
    }
}

// Returns false in case of errors
void PdfContentStreamReader::tryFollowXObject(PdfContent& content)
{
    PODOFO_ASSERT(m_inputs.back().Canvas != nullptr);
    const PdfResources* resources;
    const PdfObject* xobjraw = nullptr;
    unique_ptr<PdfXObject> xobj;
    if (content.Stack.GetSize() != 1
        || !content.Stack[0].TryGetName(content.Name)
        || (resources = m_inputs.back().Canvas->GetResources()) == nullptr
        || (xobjraw = resources->GetResource("XObject", *content.Name)) == nullptr
        || !PdfXObject::TryCreateFromObject(const_cast<PdfObject&>(*xobjraw), xobj))
    {
        content.Warnings |= PdfContentWarnings::InvalidXObject;
        return;
    }

    content.XObject.reset(xobj.release());
    content.Type = PdfContentType::DoXObject;

    if (isCalledRecursively(xobjraw))
    {
        content.Warnings |= PdfContentWarnings::RecursiveXObject;
        return;
    }

    if (content.XObject->GetType() == PdfXObjectType::Form
        && (m_args.Flags & PdfContentReaderFlags::DontFollowXObjectForms) == PdfContentReaderFlags::None)
    {
        m_inputs.push_back({
            content.XObject,
            std::make_shared<PdfCanvasInputDevice>(static_cast<const PdfXObjectForm&>(*content.XObject)),
            dynamic_cast<const PdfCanvas*>(content.XObject.get()) });
    }
}

// Returns false in case of EOF
bool PdfContentStreamReader::tryReadInlineImgData(charbuff& data)
{
    // Consume one whitespace between ID and data
    char ch;
    if (!m_inputs.back().Device->Read(ch))
        return false;

    // Read until we find the real "EI" end marker.
    // The challenge is that "EI" followed by whitespace can appear inside
    // the image data (especially in ASCII85 encoded data).
    // We use a heuristic: after finding "EI" + whitespace, we read ahead
    // a few more bytes and check if they look like valid PDF content
    // (e.g. "Q", "q", "BT", "cm", numbers, etc.) rather than binary/encoded data.
    enum class ReadEIStatus
    {
        ReadE,
        ReadI,
        ReadWhiteSpace
    };

    ReadEIStatus status = ReadEIStatus::ReadE;
    unsigned readCount = 0;
    while (m_inputs.back().Device->Read(ch))
    {
        switch (status)
        {
            case ReadEIStatus::ReadE:
            {
                if (ch == 'E')
                    status = ReadEIStatus::ReadI;

                break;
            }
            case ReadEIStatus::ReadI:
            {
                if (ch == 'I')
                    status = ReadEIStatus::ReadWhiteSpace;
                else
                    status = ReadEIStatus::ReadE;

                break;
            }
            case ReadEIStatus::ReadWhiteSpace:
            {
                if (PdfTokenizer::IsWhitespace(ch))
                {
                    // Found "EI" + whitespace candidate.
                    // Read the next whitespace-delimited token and check if it's
                    // a valid PDF operator (Q, q, BT, ET, cm, re, etc.)
                    char lookahead[64];
                    unsigned lookaheadLen = 0;
                    bool isRealEI = false;

                    // Skip additional whitespace
                    while (lookaheadLen == 0 && m_inputs.back().Device->Read(lookahead[0]))
                    {
                        if (!PdfTokenizer::IsWhitespace(lookahead[0]))
                        {
                            lookaheadLen = 1;
                            break;
                        }
                    }

                    // Read until next whitespace or special char to get a full token
                    while (lookaheadLen < 63 && m_inputs.back().Device->Read(lookahead[lookaheadLen]))
                    {
                        if (PdfTokenizer::IsWhitespace(lookahead[lookaheadLen])
                            || lookahead[lookaheadLen] == '/' || lookahead[lookaheadLen] == '<'
                            || lookahead[lookaheadLen] == '[' || lookahead[lookaheadLen] == '(')
                            break;
                        lookaheadLen++;
                    }

                    // Check if the token is a valid PDF operator or number
                    if (lookaheadLen > 0 && lookaheadLen <= 10)
                    {
                        std::string token(lookahead, lookaheadLen);
                        // Common PDF operators that appear after inline images
                        static const char* validOps[] = {
                            "Q", "q", "BT", "ET", "cm", "re", "BI", "Do", "S", "f",
                            "W", "n", "m", "l", "c", "h", "gs", "CS", "cs", "BX", "EX",
                            nullptr
                        };
                        for (const char** op = validOps; *op != nullptr; op++)
                        {
                            if (token == *op)
                            {
                                isRealEI = true;
                                break;
                            }
                        }
                        // Also valid if it's a number (operand for next operator)
                        if (!isRealEI)
                        {
                            bool isNum = true;
                            for (unsigned k = 0; k < lookaheadLen; k++)
                            {
                                char c = lookahead[k];
                                if (!((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+'))
                                {
                                    isNum = false;
                                    break;
                                }
                            }
                            if (isNum)
                                isRealEI = true;
                        }
                    }

                    if (isRealEI)
                    {
                        data = bufferview(m_buffer->data(), readCount - 2);
                        return true;
                    }
                    else
                    {
                        // False positive - add whitespace + lookahead to buffer
                        if (m_buffer->size() <= readCount + lookaheadLen + 2)
                            m_buffer->resize((readCount + lookaheadLen + 3) * 2);

                        m_buffer->data()[readCount] = ch;
                        readCount++;
                        for (unsigned k = 0; k < lookaheadLen; k++)
                        {
                            m_buffer->data()[readCount] = lookahead[k];
                            readCount++;
                        }
                        status = ReadEIStatus::ReadE;
                        continue;
                    }
                }
                else
                    status = ReadEIStatus::ReadE;

                break;
            }
        }

        if (m_buffer->size() == readCount)
        {
            // image is larger than buffer => resize buffer
            m_buffer->resize(m_buffer->size() * 2);
        }

        m_buffer->data()[readCount] = ch;
        readCount++;
    }

    return false;
}

void PdfContentStreamReader::handleWarnings()
{
    if ((m_args.Flags & PdfContentReaderFlags::ThrowOnWarnings) != PdfContentReaderFlags::None)
        PODOFO_RAISE_ERROR_INFO(PdfErrorCode::InvalidContentStream, "Unsupported PostScript content");
}

bool PdfContentStreamReader::isCalledRecursively(const PdfObject* xobj)
{
    // Determines if the given object is called recursively
    for (auto& input : m_inputs)
    {
        if (input.Canvas->GetContentsObject() == xobj)
            return true;
    }

    return false;
}
