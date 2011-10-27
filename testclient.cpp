/*
 * This file is part of the qtkeychain library
 *
 * Copyright (C) 2011 Frank Osterfeld <frank.osterfeld@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
#include <QCoreApplication>
#include <QStringList>

#include "keychain.h"
#include <iostream>


int printUsage() {
    std::cerr << "testclient store <account> <password>" << std::endl;
    std::cerr << "testclient restore <account>" << std::endl;
    std::cerr << "testclient delete <account>" << std::endl;
    return 1;
}

int main( int argc, char** argv ) {
    QCoreApplication app( argc, argv );
    const QStringList args = app.arguments();
    if ( args.count() < 2 )
        return printUsage();

    QStringList::ConstIterator it = args.constBegin();
    ++it;

    if ( *it == QLatin1String("store") ) {
        if ( ++it == args.constEnd() )
            return printUsage();
        const QString acc = *it;
        if ( ++it == args.constEnd() )
            return printUsage();
        const QString pass = *it;
        if ( ++it != args.constEnd() )
            return printUsage();
        Keychain k( QLatin1String("qtkeychain-testclient") );
        k.writePassword( acc, pass, Keychain::ForceOverwrite );
        if ( k.error() ) {
            std::cerr << "Storing password failed: " << qPrintable(k.errorString()) << std::endl;
            return 1;
        }
        std::cout << "Password stored successfully" << std::endl;
    } else if ( *it == QLatin1String("restore") ) {
        if ( ++it == args.constEnd() )
            return printUsage();
        const QString acc = *it;
        if ( ++it != args.constEnd() )
            return printUsage();
        Keychain k( QLatin1String("qtkeychain-testclient") );
        const QString pw = k.readPassword( acc );
        if ( k.error() ) {
            std::cerr << "Restoring password failed: " << qPrintable(k.errorString()) << std::endl;
            return 1;
        }
        std::cout << qPrintable(pw) << std::endl;
    } else if ( *it == QLatin1String("delete") ) {
        if ( ++it == args.constEnd() )
            return printUsage();
        const QString acc = *it;
        if ( ++it != args.constEnd() )
            return printUsage();
        Keychain k( QLatin1String("qtkeychain-testclient") );
        k.deletePassword( acc );
        if ( k.error() ) {
            std::cerr << "Deleting password failed: " << qPrintable(k.errorString()) << std::endl;
            return 1;
        }
        std::cout << "Password deleted successfully" << std::endl;
    } else {
        return printUsage();
    }
}

